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

