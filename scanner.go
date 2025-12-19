package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// FileInfo хранит данные об одном файле.
type FileInfo struct {
	Path string // Полный путь
	Name string // Имя файла
	Size int64  // Размер в байтах
	Hash string // Хэш SHA-256 (вычисляется только при необходимости)
}

// Stats для атомарного счетчика прогресса.
type Stats struct {
	TotalFiles      int64
	DuplicateGroups int64
	Errors          int64
}

// Scanner инкапсулирует логику поиска.
type Scanner struct {
	config Config
	stats  Stats // Используем атомики для конкурентного доступа
}

func NewScanner(cfg Config) *Scanner {
	return &Scanner{config: cfg}
}

// GetStats возвращает текущую статистику (безопасно для конкурентного чтения).
func (s *Scanner) GetStats() Stats {
	return Stats{
		TotalFiles:      atomic.LoadInt64(&s.stats.TotalFiles),
		DuplicateGroups: atomic.LoadInt64(&s.stats.DuplicateGroups),
		Errors:          atomic.LoadInt64(&s.stats.Errors),
	}
}

// Run запускает весь пайплайн обработки.
func (s *Scanner) Run() ([][]FileInfo, error) {
	// Шаг 1: Сбор всех файлов (быстрый проход)
	allFiles, err := s.scanFileSystem()
	if err != nil {
		return nil, err
	}

	// Шаг 2: Группировка кандидатов (отсеиваем явно уникальные файлы)
	candidates := s.groupCandidates(allFiles)

	// Шаг 3: Уточнение (вычисление хэшей конкурентно, если нужно)
	finalGroups := s.processCandidates(candidates)

	return finalGroups, nil
}

// scanFileSystem обходит директорию рекурсивно.
func (s *Scanner) scanFileSystem() ([]FileInfo, error) {
	var files []FileInfo

	err := filepath.WalkDir(s.config.DirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			atomic.AddInt64(&s.stats.Errors, 1)
			return nil
		}
		if !d.IsDir() {
			info, err := d.Info()
			if err == nil {
				files = append(files, FileInfo{
					Path: path,
					Name: d.Name(),
					Size: info.Size(),
				})
				atomic.AddInt64(&s.stats.TotalFiles, 1)
			}
		}
		return nil
	})
	return files, err
}

// groupCandidates выполняет "грубую" группировку перед тяжелой обработкой.
func (s *Scanner) groupCandidates(files []FileInfo) [][]FileInfo {
	groups := make(map[string][]FileInfo)

	for _, f := range files {
		var key string
		switch s.config.Mode {
		case "name_size", "combined":
			key = fmt.Sprintf("%s|%d", f.Name, f.Size)
		case "hash":
			// ОПТИМИЗАЦИЯ: Сначала группируем ТОЛЬКО по размеру.
			key = fmt.Sprintf("%d", f.Size)
		}
		groups[key] = append(groups[key], f)
	}

	var result [][]FileInfo
	for _, group := range groups {
		if len(group) > 1 {
			result = append(result, group)
		}
	}
	return result
}

// processCandidates обрабатывает кандидатов (считает хэши конкурентно).
func (s *Scanner) processCandidates(groups [][]FileInfo) [][]FileInfo {
	if s.config.Mode == "name_size" {
		atomic.StoreInt64(&s.stats.DuplicateGroups, int64(len(groups)))
		return groups
	}

	// Подготавливаем плоский список файлов для воркеров
	filesToHash := make([]*FileInfo, 0)
	for i := range groups {
		for j := range groups[i] {
			filesToHash = append(filesToHash, &groups[i][j])
		}
	}

	// --- WORKER POOL ПАТТЕРН ---

	// Создаем буферизированный канал.
	// Буфер позволяет main-горутине быстро закинуть задачи и не блокироваться на каждой отправке.
	jobs := make(chan *FileInfo, len(filesToHash))
	var wg sync.WaitGroup

	// Запускаем воркеров (потребителей)
	for w := 0; w < s.config.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done() // Сработает, когда цикл for ниже завершится

			// ЦИКЛ ОБРАБОТКИ ЗАДАЧ:
			// range по каналу работает до тех пор, пока канал не будет ЗАКРЫТ (closed)
			// и в нем не закончатся данные.
			for file := range jobs {
				hash, err := computeHash(file.Path)
				if err != nil {
					atomic.AddInt64(&s.stats.Errors, 1)
					file.Hash = "error"
				} else {
					file.Hash = hash
				}
			}
			// Сюда мы попадаем ТОЛЬКО после того, как вызовется close(jobs)
			// и воркер дочитает всё, что осталось в канале.
		}()
	}

	// Отправляем задачи (производитель)
	for _, f := range filesToHash {
		jobs <- f
	}

	// ВАЖНО: Правильная остановка (Graceful Shutdown)
	// Мы обязаны закрыть канал jobs, когда задачи закончились.
	// Это посылает сигнал всем воркерам: "Новых данных не будет, доделывайте текущие и выходите из цикла range".
	// Если забыть эту строку, воркеры вечно будут ждать данных (deadlock).
	close(jobs)

	// Блокируем выполнение main-горутины, пока все воркеры не закончат работу (wg.Done).
	wg.Wait()

	// --- ФИНАЛЬНАЯ ПЕРЕГРУППИРОВКА ПО ХЭШУ ---
	finalGroups := make(map[string][]FileInfo)
	for _, f := range filesToHash {
		if f.Hash == "error" {
			continue
		}
		key := f.Hash
		if s.config.Mode == "combined" {
			key = fmt.Sprintf("%s|%s", f.Name, f.Hash)
		}
		finalGroups[key] = append(finalGroups[key], *f)
	}

	var result [][]FileInfo
	for _, group := range finalGroups {
		if len(group) > 1 {
			result = append(result, group)
		}
	}

	atomic.StoreInt64(&s.stats.DuplicateGroups, int64(len(result)))
	return result
}

// computeHash читает файл и возвращает SHA-256 хэш.
func computeHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}
