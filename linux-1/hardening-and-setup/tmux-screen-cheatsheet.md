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
      <td style="text-align:left"><code>^a ^d</code>  <code>^a :detach</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">list sessions</td>
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

