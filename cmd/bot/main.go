package main

import (
	"log"
	"os"
	"strings"
	"vpn-conv/internal/service"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

func main() {
	token := os.Getenv("BOT_TOKEN")
	if token == "" {
		log.Fatal("BOT_TOKEN not set")
	}

	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Authorized on account %s", bot.Self.UserName)

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

			doc := tgbotapi.FileBytes{
				Name:  "config." + format,
				Bytes: []byte(output),
			}
			msg := tgbotapi.NewDocument(update.Message.Chat.ID, doc)
			bot.Send(msg)
		}
	}
}
