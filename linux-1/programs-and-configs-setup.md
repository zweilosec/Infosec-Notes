---
description: >-
  A collection of useful programs and configurations for getting your home box
  set up for pre-engagement use. I think I want to rename this page to something
  else...can't think of a good title right now
---

# Programs & Configs Setup



### TMUX

tmux can keep alive sessions if you lose ssh sessions etc, can split panes and more:

```text
tmux new -s <session_name> 
ctrl-b = prefix key (enables addnl commands) 
+[%] vertical pane  
+["] horizontal pane 
+[alt-space] switch pane between horizontal or vertical
+[arrow_keys] move between panes 
+[z] zoom in/out on pane 
+[?] help for tmux 
+[t] timer
```

tmux plugins:

* tmux logging plugin \(get this!!\) can save log of tmux windows
* [better mouse mode](https://github.com/NHDaly/tmux-better-mouse-mode)

### Tmux

Config from [ippsec](https://www.youtube.com/watch?v=Lqehvpe_djs).

```text
#set prefix
set -g prefix C-a
bind C-a send-prefix
unbind C-b

set -g history-limit 100000
set -g allow-rename off

bind-key j command-prompt -p "Join pane from:" "join-pane -s '%%'"
bind-key s command-prompt -p "Send pane to:" "joian-pane -t '%%'"

set-window-option -g mode-keys vi

run-shell /opt/tmux-logging/logging.tmux
```

First press the prefix `ctrl + b`\(default, Ippsec changes it to Ctrl+a\) then release the buttons and press the combination you want.

Create new named session: `tmux new -s [Name]`

Create new window: `prefix + c`

Rename window: `prefix + ,`

Change panes: `prefix + #`

List windows: `prefix + w`

Vertical split: `prefix + %`

Horizontal split: `prefix + "`

Join panes: `prefix + s #`

Zoom in/out to panes: `prefix + z`

Make sub-terminal its own window: `prefix + !`

Enter vim mode: `prefix + ]` -&gt; Search with `?` in vi mode then press `space` to start copying.  Press `prefix + ]` to paste

Kill session by tag:`tmux kill-session -t X`

Kill pane: `prefix + &`

