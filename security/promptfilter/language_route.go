package promptfilter

import (
	"hash/maphash"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	whatlanggo "github.com/abadojack/whatlanggo"
)

const (
	nonZhEnMinimumForeignScriptLetters = 4
	nonZhEnStrongForeignScriptLetters  = 12
	nonZhEnMinimumLatinWords           = 10
	nonZhEnMinimumLatinLetters         = 48
	nonZhEnMaxSamples                  = 3
	nonZhEnMaxSampleBytes              = 768
	nonZhEnMaxTotalSampleBytes         = 4 * 1024
	nonZhEnLatinWindowBytes            = 1024
	nonZhEnLatinWindowOverlapBytes     = 256
	nonZhEnLanguageCacheMinBytes       = 256
	nonZhEnLanguageCacheEntries        = 8192
)

type nonZhEnLanguageCacheKey struct {
	first  uint64
	second uint64
	length int
	domain uint8
}

const (
	nonZhEnCacheDomainFullPartition uint8 = iota
	nonZhEnCacheDomainLatinWindow
)

type nonZhEnLanguageDecisionCache struct {
	mu      sync.RWMutex
	entries map[nonZhEnLanguageCacheKey]bool
	order   []nonZhEnLanguageCacheKey
	next    int
}

var nonZhEnLanguageCache = nonZhEnLanguageDecisionCache{
	entries: make(map[nonZhEnLanguageCacheKey]bool, nonZhEnLanguageCacheEntries),
	order:   make([]nonZhEnLanguageCacheKey, 0, nonZhEnLanguageCacheEntries),
}

var (
	nonZhEnLanguageHashSeedFirst  = maphash.MakeSeed()
	nonZhEnLanguageHashSeedSecond = maphash.MakeSeed()
)

// nonEnglishLatinMarkerGroups are deliberately high-precision function-word
// and prose-marker groups. They cover complete but statistically short Latin
// sentences that whatlanggo cannot classify reliably. A single loanword,
// product name, or identifier is never enough to satisfy a group.
var nonEnglishLatinMarkerGroups = [][]string{
	{"hola", "gracias", "revisa", "respuesta", "explica", "solicitud", "porque", "para", "esta", "este"},
	{"bonjour", "merci", "avec", "pour", "dans", "cette", "pourquoi", "requete", "réponse", "expliquez"},
	{"bitte", "warum", "nicht", "antwort", "anfrage", "prüfen", "erklaeren", "erklären", "diese", "dieser"},
	{"obrigado", "resposta", "solicitacao", "solicitação", "porque", "para", "esta", "explique", "revise", "você"},
	{"ciao", "grazie", "questa", "questo", "perche", "perché", "spiega", "richiesta", "risposta", "controlla"},
	{"alstublieft", "waarom", "antwoord", "verzoek", "controleer", "uitleggen", "deze", "voor", "niet", "met"},
	{"proszę", "dlaczego", "odpowiedz", "żądanie", "sprawdź", "wyjaśnij", "jest", "oraz", "nie", "dla"},
	{"lütfen", "lutfen", "neden", "istek", "istegin", "yanıt", "yanitini", "kontrol", "açıkla", "aciklayin", "icin", "için", "degil", "değil"},
	{"tolong", "mengapa", "permintaan", "jawaban", "periksa", "jelaskan", "dengan", "untuk", "yang", "tidak"},
	{"vui", "long", "kiem", "tra", "phan", "hoi", "giai", "thich", "tai", "sao", "yeu", "cau", "khong"},
	{"va rog", "de ce", "raspuns", "răspuns", "cerere", "verifica", "explica", "pentru", "acest", "aceasta"},
	{"por favor", "respuesta", "solicitud", "revisar", "explicar", "porque", "para", "esta", "como", "gracias"},
}

// LooksLikeNonChineseEnglishNaturalLanguage reports whether bounded readable
// prompt text contains enough evidence of a natural language other than
// Chinese or English. It is a routing hint only: callers must never use it to
// block a request. URL/path/hash/code noise is excluded before the statistical
// Latin-language pass; all Unicode letters remain covered by the script pass.
func LooksLikeNonChineseEnglishNaturalLanguage(text string) bool {
	if strings.TrimSpace(text) == "" {
		return false
	}
	if len(text) < nonZhEnLanguageCacheMinBytes {
		return containsForeignNaturalScript(text) || containsForeignLatinNaturalLanguage(text)
	}
	key := newNonZhEnLanguageCacheKey(text, nonZhEnCacheDomainFullPartition)
	if result, ok := nonZhEnLanguageCache.get(key); ok {
		return result
	}
	result := containsForeignNaturalScript(text) || containsForeignLatinNaturalLanguage(text)
	nonZhEnLanguageCache.put(key, result)
	return result
}

func newNonZhEnLanguageCacheKey(text string, domain uint8) nonZhEnLanguageCacheKey {
	var first, second maphash.Hash
	first.SetSeed(nonZhEnLanguageHashSeedFirst)
	second.SetSeed(nonZhEnLanguageHashSeedSecond)
	_, _ = first.WriteString(text)
	_, _ = second.WriteString(text)
	return nonZhEnLanguageCacheKey{first: first.Sum64(), second: second.Sum64(), length: len(text), domain: domain}
}

func (cache *nonZhEnLanguageDecisionCache) get(key nonZhEnLanguageCacheKey) (bool, bool) {
	cache.mu.RLock()
	result, ok := cache.entries[key]
	cache.mu.RUnlock()
	return result, ok
}

func (cache *nonZhEnLanguageDecisionCache) put(key nonZhEnLanguageCacheKey, result bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if _, exists := cache.entries[key]; exists {
		return
	}
	if len(cache.order) < cap(cache.order) {
		cache.order = append(cache.order, key)
	} else {
		delete(cache.entries, cache.order[cache.next])
		cache.order[cache.next] = key
		cache.next = (cache.next + 1) % len(cache.order)
	}
	cache.entries[key] = result
}

func containsForeignNaturalScript(text string) bool {
	var scriptCounts [25]int
	var scriptWords [25]int
	totalLetters := 0
	lastScript := -1
	for _, r := range text {
		if !unicode.IsLetter(r) {
			lastScript = -1
			continue
		}
		totalLetters++
		if unicode.Is(unicode.Han, r) || unicode.Is(unicode.Latin, r) || unicode.Is(unicode.Bopomofo, r) {
			lastScript = -1
			continue
		}
		bucket := foreignScriptBucket(r)
		scriptCounts[bucket]++
		if lastScript != bucket {
			scriptWords[bucket]++
		}
		lastScript = bucket
	}
	if totalLetters == 0 {
		return false
	}
	for index, count := range scriptCounts {
		if count < nonZhEnMinimumForeignScriptLetters {
			continue
		}
		// A short coherent foreign-script phrase is decisive. In a much larger
		// English/Chinese partition, require at least twelve letters so a lone
		// personal name or mathematical variable cannot redirect the request.
		if count >= 20 || (scriptWords[index] >= 2 && (count >= nonZhEnStrongForeignScriptLetters || count*8 >= totalLetters)) {
			return true
		}
	}
	return false
}

func foreignScriptBucket(r rune) int {
	switch {
	case unicode.Is(unicode.Cyrillic, r):
		return 0
	case unicode.Is(unicode.Arabic, r):
		return 1
	case unicode.Is(unicode.Devanagari, r):
		return 2
	case unicode.Is(unicode.Hebrew, r):
		return 3
	case unicode.Is(unicode.Greek, r):
		return 4
	case unicode.Is(unicode.Hiragana, r):
		return 5
	case unicode.Is(unicode.Katakana, r):
		return 6
	case unicode.Is(unicode.Hangul, r):
		return 7
	case unicode.Is(unicode.Thai, r):
		return 8
	case unicode.Is(unicode.Bengali, r):
		return 9
	case unicode.Is(unicode.Georgian, r):
		return 10
	case unicode.Is(unicode.Armenian, r):
		return 11
	case unicode.Is(unicode.Ethiopic, r):
		return 12
	case unicode.Is(unicode.Gujarati, r):
		return 13
	case unicode.Is(unicode.Gurmukhi, r):
		return 14
	case unicode.Is(unicode.Kannada, r):
		return 15
	case unicode.Is(unicode.Tamil, r):
		return 16
	case unicode.Is(unicode.Telugu, r):
		return 17
	case unicode.Is(unicode.Malayalam, r):
		return 18
	case unicode.Is(unicode.Oriya, r):
		return 19
	case unicode.Is(unicode.Myanmar, r):
		return 20
	case unicode.Is(unicode.Sinhala, r):
		return 21
	case unicode.Is(unicode.Khmer, r):
		return 22
	default:
		return 24
	}
}

func containsForeignLatinNaturalLanguage(text string) bool {
	var shortLines strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if containsForeignLatinSpan(line) {
			return true
		}
		if len(line) == 0 || len(line) >= nonZhEnLatinWindowOverlapBytes {
			continue
		}
		if shortLines.Len() > 0 {
			shortLines.WriteByte('\n')
		}
		shortLines.WriteString(line)
		if shortLines.Len() >= nonZhEnLatinWindowBytes {
			if containsForeignLatinSpan(shortLines.String()) {
				return true
			}
			shortLines.Reset()
		}
	}
	return shortLines.Len() > 0 && containsForeignLatinSpan(shortLines.String())
}

func containsForeignLatinSpan(text string) bool {
	for start := 0; start < len(text); {
		end := start + nonZhEnLatinWindowBytes
		if end >= len(text) {
			end = len(text)
		} else {
			for end > start && !utf8.RuneStart(text[end]) {
				end--
			}
		}
		if containsForeignLatinWindow(text[start:end]) {
			return true
		}
		if end == len(text) {
			break
		}
		next := end - nonZhEnLatinWindowOverlapBytes
		for next < end && !utf8.RuneStart(text[next]) {
			next++
		}
		if next <= start {
			next = end
		}
		start = next
	}
	return false
}

func containsForeignLatinWindow(text string) bool {
	if len(text) >= nonZhEnLanguageCacheMinBytes {
		key := newNonZhEnLanguageCacheKey(text, nonZhEnCacheDomainLatinWindow)
		if result, ok := nonZhEnLanguageCache.get(key); ok {
			return result
		}
		result := inspectForeignLatinWindow(text)
		nonZhEnLanguageCache.put(key, result)
		return result
	}
	return inspectForeignLatinWindow(text)
}

func inspectForeignLatinWindow(text string) bool {
	samples, allWords, latinLetters, nonASCII := latinNaturalLanguageSamples(text)
	if len(allWords) == 0 {
		return false
	}
	if hasNonEnglishLatinMarkers(allWords) {
		return true
	}
	// Several accented Latin letters in a real prose fragment are enough to
	// establish non-English language evidence even when the statistical model
	// considers a short sentence ambiguous.
	if nonASCII >= 4 && latinLetters >= 20 && nonASCII*20 >= latinLetters {
		return true
	}
	for _, sample := range samples {
		info := whatlanggo.Detect(sample)
		if info.IsReliable() && info.Lang != whatlanggo.Eng && info.Lang != whatlanggo.Cmn {
			return true
		}
	}
	return false
}

func latinNaturalLanguageSamples(text string) (samples []string, allWords []string, latinLetters int, nonASCII int) {
	lines := strings.Split(text, "\n")
	totalSampleBytes := 0
	for _, line := range lines {
		words, letters, accented := latinWordsFromLine(line)
		if len(words) == 0 {
			continue
		}
		latinLetters += letters
		nonASCII += accented
		allWords = append(allWords, words...)
		if len(samples) >= nonZhEnMaxSamples-1 || len(words) < nonZhEnMinimumLatinWords || letters < nonZhEnMinimumLatinLetters {
			continue
		}
		sample := boundedWordSample(words, nonZhEnMaxSampleBytes)
		if sample == "" || totalSampleBytes+len(sample) > nonZhEnMaxTotalSampleBytes {
			continue
		}
		samples = append(samples, sample)
		totalSampleBytes += len(sample)
	}

	if len(allWords) >= nonZhEnMinimumLatinWords && latinLetters >= nonZhEnMinimumLatinLetters && len(samples) < nonZhEnMaxSamples {
		remaining := nonZhEnMaxTotalSampleBytes - totalSampleBytes
		if remaining > nonZhEnMaxSampleBytes {
			remaining = nonZhEnMaxSampleBytes
		}
		if aggregate := boundedWordSample(allWords, remaining); aggregate != "" {
			samples = append(samples, aggregate)
		}
	}
	return samples, allWords, latinLetters, nonASCII
}

func latinWordsFromLine(line string) ([]string, int, int) {
	if strings.TrimSpace(line) == "" {
		return nil, 0, 0
	}
	words := make([]string, 0, 16)
	latinLetters, nonASCII := 0, 0
	for _, field := range strings.Fields(line) {
		if machineLikeLanguageToken(field) {
			continue
		}
		for _, word := range latinWords(field) {
			if machineLikeLanguageWord(word) {
				continue
			}
			wordRunes := utf8.RuneCountInString(word)
			if wordRunes < 2 || wordRunes > 30 {
				continue
			}
			words = append(words, word)
			for _, r := range word {
				if unicode.Is(unicode.Latin, r) {
					latinLetters++
					if r > unicode.MaxASCII {
						nonASCII++
					}
				}
			}
		}
	}
	return words, latinLetters, nonASCII
}

func machineLikeLanguageToken(token string) bool {
	trimmed := strings.Trim(token, "\"'.,!?，。！？:：()")
	lower := strings.ToLower(trimmed)
	return lower == "" || strings.Contains(lower, "://") || strings.HasPrefix(lower, "www.")
}

func machineLikeLanguageWord(word string) bool {
	switch word {
	case "fail", "failed", "failure", "error", "errors", "pass", "passed", "success", "unknown", "panic", "traceback", "code", "message", "status",
		"instruction", "instructions", "environment", "context", "cwd", "shell", "current", "date", "timezone", "time", "asia", "shanghai",
		"pf", "hit", "powershell", "npm", "lint", "validated", "behavior", "latest", "checks", "test", "tests", "build", "slow",
		"codex", "users", "documents":
		return true
	default:
		return false
	}
}

func latinWords(value string) []string {
	var words []string
	var current strings.Builder
	previousLower := false
	flush := func() {
		if current.Len() == 0 {
			return
		}
		words = append(words, strings.ToLower(current.String()))
		current.Reset()
		previousLower = false
	}
	for _, r := range value {
		if unicode.Is(unicode.Latin, r) {
			if current.Len() > 0 && unicode.IsUpper(r) && previousLower {
				flush()
			}
			current.WriteRune(r)
			previousLower = unicode.IsLower(r)
			continue
		}
		if current.Len() > 0 && unicode.Is(unicode.Mn, r) {
			current.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return words
}

func boundedWordSample(words []string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	var sample strings.Builder
	for _, word := range words {
		extra := len(word)
		if sample.Len() > 0 {
			extra++
		}
		if sample.Len()+extra > maxBytes {
			break
		}
		if sample.Len() > 0 {
			sample.WriteByte(' ')
		}
		sample.WriteString(word)
	}
	return sample.String()
}

func hasNonEnglishLatinMarkers(words []string) bool {
	seenWords := make(map[string]struct{}, len(words))
	for _, word := range words {
		seenWords[word] = struct{}{}
	}
	joined := " " + strings.Join(words, " ") + " "
	for _, group := range nonEnglishLatinMarkerGroups {
		seenMarkers := make(map[string]struct{}, 4)
		for _, marker := range group {
			matched := false
			if strings.Contains(marker, " ") {
				matched = strings.Contains(joined, " "+marker+" ")
			} else {
				_, matched = seenWords[marker]
			}
			if matched {
				seenMarkers[marker] = struct{}{}
			}
		}
		if len(seenMarkers) >= 3 {
			return true
		}
	}
	return false
}
