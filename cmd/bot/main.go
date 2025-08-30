package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"vpn-conv/internal/service"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// getFileExtension returns the correct file extension for a given format.
func getFileExtension(format string) string {
	switch format {
	case "clash":
		return "yaml"
	case "v2ray", "singbox":
		return "json"
	case "raw":
		return "txt"
	default:
		return "txt" // Default to text for unknown formats
	}
}

func main() {
	log.Println("Starting bot...")
	log.Println("Reading BOT_TOKEN from environment...")
	token := os.Getenv("BOT_TOKEN")
	if token == "" {
		log.Fatal("FATAL: BOT_TOKEN environment variable not set.")
	}

	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		log.Fatalf("FATAL: Failed to create bot API: %v", err)
	}

	log.Printf("Authorized on account %s", bot.Self.UserName)
	log.Println("Bot is now running and listening for commands.")

	renderer := service.NewRenderer()

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message == nil || !update.Message.IsCommand() {
			continue
		}

		switch update.Message.Command() {
		case "start":
			msg := tgbotapi.NewMessage(update.Message.Chat.ID,
				"Halo! Gunakan /convert <link> <format> untuk konversi akun VPN.\n"+
					"Format tersedia: clash, singbox, v2ray, raw")
			bot.Send(msg)

		case "convert":
			args := strings.Fields(update.Message.CommandArguments())
			if len(args) != 2 {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID,
					"Format salah. Gunakan: /convert <link> <format>")
				bot.Send(msg)
				continue
			}

			link := args[0]
			format := strings.ToLower(args[1])

			output, err := renderer.Convert(link, format)
			if err != nil {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Error: "+err.Error())
				bot.Send(msg)
				continue
			}

			// Use the new function to get the correct file extension.
			ext := getFileExtension(format)
			fileName := fmt.Sprintf("config.%s", ext)

			doc := tgbotapi.FileBytes{
				Name:  fileName,
				Bytes: []byte(output),
			}
			msg := tgbotapi.NewDocument(update.Message.Chat.ID, doc)
			bot.Send(msg)
		}
	}
}
