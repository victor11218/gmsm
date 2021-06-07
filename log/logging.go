package log

import (
	"fmt"
)

var (
	black        = string([]byte{27, 91, 57, 48, 109})
	red          = string([]byte{27, 91, 57, 49, 109})
	green        = string([]byte{27, 91, 57, 50, 109})
	yellow       = string([]byte{27, 91, 57, 51, 109})
	blue         = string([]byte{27, 91, 57, 52, 109})
	magenta      = string([]byte{27, 91, 57, 53, 109})
	cyan         = string([]byte{27, 91, 57, 54, 109})
	white        = string([]byte{27, 91, 57, 55, 59, 52, 48, 109})
	reset        = string([]byte{27, 91, 48, 109})
	disableColor = false
)

// 输出有颜色的字体
func colorPrint(s string, color string) {
	fmt.Println(color, s, reset)
}

// 输出分离颜色的字符
func colorSplitPrint(strHeadColor string, strHead string, strBodyColor string, strBody string) {
	fmt.Println(strHeadColor, strHead, reset, strBodyColor, strBody, reset)
}

func Error(s string) {
	colorSplitPrint(magenta, "【ERRO】", red, s)
}

func Info(s string) {
	colorSplitPrint(magenta, "【INFO】", green, s)
}

func Warning(s string) {
	colorSplitPrint(magenta, "【WARN】", yellow, s)
}

func Debug(s string) {
	colorSplitPrint(magenta, "【DEBU】", blue, s)
}
