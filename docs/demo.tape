Output docs/demo.gif

Require python3

Set Shell "bash"
Set FontSize 20
Set Width 1000
Set Height 650
Set Theme "Dracula"
Set TypingSpeed 60ms
Set Padding 20

Type "python3 agent.py --target 127.0.0.1"
Sleep 500ms
Enter

# Real wait for the scan spine + LLM report. Hidden time contributes ZERO
# duration to the exported GIF — VHS still runs the real process for its
# full ~4-4.5 min wall-clock, but none of that is recorded into the output.
# Bump Sleep here if your run tends to run longer; better to over-wait
# (idle time costs nothing in the export) than cut the report off.
Hide
Sleep 400s
Show

# Brief hold on the tail (good news / wrap-up) before scrolling back.
Sleep 2s

# Scroll all the way back up to the top of the report — the risk badge,
# summary, and highest-severity finding, i.e. the actual "hook" — instead
# of ending on low-priority findings. 280 steps comfortably overshoots any
# realistic report length; confirmed VHS clamps at the scrollback top
# rather than erroring, so overshoot is safe. Slower per-step delay than
# before (115ms vs 85ms) so the scroll itself is readable instead of a
# blur, since the final hold below was cut from 4s to make room for it.
ScrollUp@115ms 280

# Hold at the top so the headline risk + summary + top finding are readable.
Sleep 2s
