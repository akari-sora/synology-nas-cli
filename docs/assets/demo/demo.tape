# Records docs/assets/demo.gif and demo.mp4: `cd docs/assets && vhs demo/demo.tape` (https://github.com/charmbracelet/vhs).
# `demo/nas` runs the real CLI against the test suite's simulated DSM 7.1 box (tests/fakenas.py).
Output demo.gif
Output demo.mp4

Set Shell bash
Set FontSize 15
Set Width 1440
Set Height 900
Set Padding 20
Set Margin 24
Set MarginFill "#11111b"
Set BorderRadius 12
Set WindowBar Colorful
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms
Set Framerate 24

Hide
Type "source demo/setup.sh"
Enter
Sleep 500ms
Show

Type "# 1. Audit: read-only, one command"
Enter
Type "nas incident"
Sleep 400ms
Enter
Sleep 4.5s

Type "# 2. Fix what it found: every change is applied, read back, then audited again"
Enter
Type "nas incident fix --yes --ransom-scan"
Sleep 400ms
Enter
Sleep 7s
