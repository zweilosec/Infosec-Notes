# TMUX/Screen Cheatsheet

TMUX and screen are extremely useful tools for maintaining sessions through reverse tunnels and other fragile connections.  They allow for reconnection of sessions that become detached \(disconnected\) where the process is still running but there was some sort of network interruption.  

They both have a very handy function where each window can be split either vertically or horizontally in to separate panes.  I am not sure what the actual limit to the number of panes may be, but I regularly split my windows into four panes comfortably.

Screen is fairly ubiquitous in most Linux distributions, however TMUX is a program that will likely have to be installed on the machine you are connecting to.  Screen is fairly old and does not get feature updates anymore \(as far as I am aware\), while TMUX is newer and has many plugins which can be used to extend its functionality. 

{% hint style="info" %}
**`^`** is shorthand for the **`CTRL`** key, so **`^b`** == **`CTRL + b`**. 

-----

**`^a`** is the default meta-key for **`screen`**, while **`^b`** is the default meta-key for **`TMUX`**.
{% endhint %}

## Session Management

| Action | TMUX | Screen |
| :--- | :--- | :--- |
| Start a new session | `tmux` OR `tmux new` OR `tmux new-session` | `screen` |
| Re-attach a \(local\) detached session | `tmux attach` OR `tmux attach-session` | `screen -r` |
| Re-attach an attached session \(detaching it from elsewhere\) | `tmux attach -d` OR `tmux attach-session -d` | `screen -dr` |
| Re-attach an attached session \(keeping it attached elsewhere\) | `tmux attach` OR `tmux attach-session` | `screen -x` |
| Detach from currently attached session | `^b d` OR `^b :detach` | `^a ^d` OR `^a :detach` |
| list sessions | `^b s` OR `tmux ls` OR `tmux list-sessions` | `screen -ls` |

|  |
| :--- |


## Pane Management

| Action | TMUX | Screen |
| :--- | :--- | :--- |
| Split pane horizontally | `^b "` | \`^a |
| Split pane vertically | `^b %` | `^a S` |
| Switch to another pane | `^b o` | `^a tab` |
| Kill the current pane | `^b x` OR \(logout/`^D`\) | `^a X` |
| Close all panes except the current one | `^b !` | ----- |
| Swap location of panes | `^b ^o` | N/A |
| Show time | `^b t` | ----- |
| Show numeric identifier for all panes | `^b q` | ----- |

## Window Management

| Action | TMUX | Screen |
| :--- | :--- | :--- |
| Rename window | `^b , <new_name>` OR `^b :rename-window <new_name>` | `^a A <new_name>` |
| List windows | `^b w` | `^a w` |
| List windows \(with selection menu\) | ------ | `^a "` |
| Go to window $num | `^b $num` | `^a $num` |
| Go to previously active window | `^b l` | `^a l` |
| Go to next window | `^b n` | `^a n` |
| Go to previous window | `^b p` | `^a p` |

## MISC \(to sort\)

| Action | TMUX | Screen |
| :--- | :--- | :--- |
| See key bindings | `^b ?` | `^a ?` |
| Enter "scroll mode" | `^b [` | `^a [` |
| Scroll up in "scroll mode" | page up and up arrow | `^b` for page up or `k` for one line |
| Scroll down in "scroll mode" | page down and down arrow | `^f` for page down or `j` for one line |
| Exit "scroll mode" | `q` | `ESC` |
| Create another shell | `^b c` | `^a c` |
| Exit current shell | `^d` | `^d` |

