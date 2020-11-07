# TMUX/Screen Cheatsheet

TMUX and screen are extremely useful tools for maintaining sessions through reverse tunnels and other fragile connections.  They allow for reconnection of sessions that become detached \(disconnected\) where the process is still running but there was some sort of network interruption.  

They both have a very handy function where each window can be split either vertically or horizontally in to separate panes.  I am not sure what the actual limit to the number of panes may be, but I regularly split my windows into four panes comfortably.

Screen is fairly ubiquitous in most Linux distributions, however TMUX is a program that will likely have to be installed on the machine you are connecting to.  Screen is fairly old and does not get feature updates anymore \(as far as I am aware\), while TMUX is newer and has many plugins which can be used to extend its functionality.  Learning both will ensure you are ready no matter which may be present on the system you log into.

{% hint style="info" %}
**`^`** is shorthand for the **`CTRL`** key, so **`^b`** == **`CTRL + b`**. 

-----

**`^a`** is the default meta-key for **`screen`**, while **`^b`** is the default meta-key for **`TMUX`**.
{% endhint %}

## Session Management

<table>
  <thead>
    <tr>
      <th style="text-align:left">Action</th>
      <th style="text-align:left">TMUX</th>
      <th style="text-align:left">Screen</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Start a new session</td>
      <td style="text-align:left">
        <p><code>tmux</code>
        </p>
        <p><code>tmux new</code>
        </p>
        <p><code>tmux new-session</code>
        </p>
      </td>
      <td style="text-align:left"><code>screen</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Re-attach a (local) detached session</td>
      <td style="text-align:left">
        <p><code>tmux attach</code>
        </p>
        <p><code>tmux attach-session</code>
        </p>
      </td>
      <td style="text-align:left"><code>screen -r</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Re-attach an attached session (detaching it from elsewhere)</td>
      <td style="text-align:left">
        <p><code>tmux attach -d</code>
        </p>
        <p><code>tmux attach-session -d</code>
        </p>
      </td>
      <td style="text-align:left"><code>screen -dr</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Re-attach an attached session (keeping it attached elsewhere)</td>
      <td
      style="text-align:left">
        <p><code>tmux attach</code>
        </p>
        <p><code>tmux attach-session</code>
        </p>
        </td>
        <td style="text-align:left"><code>screen -x</code>
        </td>
    </tr>
    <tr>
      <td style="text-align:left">Detach from currently attached session</td>
      <td style="text-align:left">
        <p><code>^b d</code>
        </p>
        <p><code>^b :detach</code>
        </p>
      </td>
      <td style="text-align:left">
        <p><code>^a d</code>
        </p>
        <p><code>^a ^d</code>  <code>^a :detach</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Detach and log out</td>
      <td style="text-align:left"></td>
      <td style="text-align:left">
        <p><code>^a f</code>
        </p>
        <p><code>^a ^f</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">List sessions</td>
      <td style="text-align:left">
        <p><code>^b s</code>
        </p>
        <p><code>tmux ls</code>  <code>tmux list-sessions</code>
        </p>
      </td>
      <td style="text-align:left"><code>screen -ls</code>
      </td>
    </tr>
  </tbody>
</table>

## Pane Management

| Action | TMUX | Screen |
| :--- | :--- | :--- |
| Split pane horizontally | `^b "` | `^a S` |
| Split pane vertically | `^b %` | `^a |` |
| Switch to another pane | `^b o` | `^a tab` |
| Kill the current pane | `^b x`  | `^a X` |
| Close all panes except the current one | `^b !` | `^a Q` |
| Swap location of panes | `^b ^o` | N/A |
| Show time | `^b t` | ----- |
| Show numeric identifier for all panes | `^b q` | ----- |

## Window Management

<table>
  <thead>
    <tr>
      <th style="text-align:left">Action</th>
      <th style="text-align:left">TMUX</th>
      <th style="text-align:left">Screen</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Rename window</td>
      <td style="text-align:left">
        <p><code>^b , &lt;new_name&gt;</code>
        </p>
        <p><code>^b :rename-window &lt;new_name&gt;</code>
        </p>
      </td>
      <td style="text-align:left"><code>^a A &lt;new_name&gt;</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Create new window</td>
      <td style="text-align:left"><code>^b c</code>
      </td>
      <td style="text-align:left">
        <p><code>^a c</code>
        </p>
        <p><code>^a ^c</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">List windows</td>
      <td style="text-align:left"><code>^b w</code>
      </td>
      <td style="text-align:left"><code>^a w</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">List windows (with selection menu)</td>
      <td style="text-align:left">-----</td>
      <td style="text-align:left"><code>^a &quot;</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Go to window $num</td>
      <td style="text-align:left"><code>^b $num</code>
      </td>
      <td style="text-align:left"><code>^a $num</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Go to previously active window</td>
      <td style="text-align:left"><code>^b l</code>
      </td>
      <td style="text-align:left"><code>^a ^a</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Go to next window</td>
      <td style="text-align:left"><code>^b n</code>
      </td>
      <td style="text-align:left"><code>^a n</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Go to previous window</td>
      <td style="text-align:left"><code>^b p</code>
      </td>
      <td style="text-align:left"><code>^a p</code>
      </td>
    </tr>
  </tbody>
</table>

## MISC

<table>
  <thead>
    <tr>
      <th style="text-align:left">Action</th>
      <th style="text-align:left">TMUX</th>
      <th style="text-align:left">Screen</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">See key bindings</td>
      <td style="text-align:left"><code>^b ?</code>
      </td>
      <td style="text-align:left"><code>^a ?</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Enter &quot;scroll mode&quot;</td>
      <td style="text-align:left"><code>^b [</code>
      </td>
      <td style="text-align:left"><code>^a [</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Scroll up in &quot;scroll mode&quot;</td>
      <td style="text-align:left">
        <p><code>[page up]</code>
        </p>
        <p><code>[up arrow]</code>
        </p>
      </td>
      <td style="text-align:left">
        <p><code>^b</code> for page up</p>
        <p><code>k</code> for one line</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Scroll down in &quot;scroll mode&quot;</td>
      <td style="text-align:left">
        <p><code>[page down]</code>
        </p>
        <p><code>[down arrow]</code>
        </p>
      </td>
      <td style="text-align:left">
        <p><code>^f</code> for page down</p>
        <p><code>j</code> for one line</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Exit &quot;scroll mode&quot;</td>
      <td style="text-align:left"><code>q</code>
      </td>
      <td style="text-align:left"><code>ESC</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Exit current shell</td>
      <td style="text-align:left"><code>^d</code>
      </td>
      <td style="text-align:left"><code>^d</code>
      </td>
    </tr>
  </tbody>
</table>



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

Join panes: `prefix + s #`

Zoom in/out to panes: `prefix + z`

Make sub-terminal its own window: `prefix + !`

Enter vim mode: `prefix + ]` -&gt; Search with `?` in vi mode then press `space` to start copying. Press `prefix + ]` to paste

Kill session by tag:`tmux kill-session -t X`

Kill pane: `prefix + &`

#### tmux plugins:

* tmux logging plugin \(get this!!\) can save log of tmux windows
* [better mouse mode](https://github.com/NHDaly/tmux-better-mouse-mode)

