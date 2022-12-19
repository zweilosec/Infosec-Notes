---
description: >-
  Love it or hate it, most distros have it installed.  It's best to know at
  least how to edit files, and exit. Knowing how to exit vi is one of life's
  greatest mysteries.
---

# Vim

{% hint style="danger" %}
Not much here yet...please feel free to contribute at [my GitHub page](https://github.com/zweilosec/Infosec-Notes).
{% endhint %}



## Basic Commands

All commands must be run from Command Mode (unless otherwise specified).

| Command | Description                                                              |
| ------- | ------------------------------------------------------------------------ |
| `[ESC]` | Return to Command Mode.                                                  |
| `i`     | Enter insert (normal text edit) mode.                                    |
| `x`     | Delete a character.  Type a number first to delete that many characters. |
| `dd`    | Delete a whole line.  Type a number first to delete that many lines.     |
| `yy`    | Yank (copy) a whole line.  Type a number first to yank that many lines.  |
| `p`     | Put (paste) contents of clipboard.                                       |
|         |                                                                          |

## How to exit Vim

{% embed url="https://github.com/hakluke/how-to-exit-vim" %}
lulz
{% endembed %}

No really, exiting vi, vim, etc. is quite simple. `[esc] :q!` will get you out every time, most of the time.  _Learning why or why not...takes a little bit longer._&#x20;

If you need to save any changes you made to a file use `[esc] :w` or `[esc] :wq` to save changes and exit.

{% hint style="info" %}
_To clarify, that's the escape key, then colon w to write changes, or colon wq to write and quit._
{% endhint %}

If you need to exit without making changes (for example when you open a read-only file by accident) type `[esc] :q!`

## Misc

* Learn vim: `vimtutor`
* [https://www.youtube.com/watch?v=OnUiHLYZgaA](https://www.youtube.com/watch?v=OnUiHLYZgaA)
* vim plugins: fuzzy finder plugin ctrlp /// surround.vim

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
