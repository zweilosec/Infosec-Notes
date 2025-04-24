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

## How to exit Vim

{% embed url="https://github.com/hakluke/how-to-exit-vim" %}
lulz
{% endembed %}

First, the most important thing to learn about vim...how to get out of it:

Exiting vi, vim, and similar editors is actually quite simple. Press `[ESC]` and type `:q`— if that does not work try adding a bang (`!`) to it, that should work nearly every time. _Understanding why it might not... well, that’s a whole different story._  

If you need to save any changes you made to a file use `[esc] :w` or `[esc] :wq` to save changes and exit.

{% hint style="info" %}
_To clarify, that's the escape key, then colon w to write changes, or colon wq to write and quit._
{% endhint %}

If you need to exit without making changes (for example when you open a read-only file by accident) type `[esc] :q!`


### Basic Vim Commands

All commands must be run from Command Mode (unless otherwise specified).

| Command | Description |
| ------- | ------------------------------------------------------------------------ |
| `[ESC]` | Return to Command Mode. |
| `i` | Enter insert (normal text edit) mode. |
| `x` | Delete a character. Type a number first to delete that many characters. |
| `dd` | Delete a whole line. Type a number first to delete that many lines. |
| `yy` | Yank (copy) a whole line. Type a number first to yank that many lines. |
| `p` | Put (paste) contents of clipboard. |
| `u` | Undo the last action. |
| `Ctrl + r` | Redo the last undone action. |
| `/text` | Search for "text" in the document. Use `n` to jump to the next occurrence. |
| `?text` | Search backwards for "text" in the document. Use `n` to jump to the next occurrence. |
| `:w` | Save changes to the file. |
| `:q` | Quit Vim. Use `:q!` to quit without saving. |
| `:wq` or `ZZ` | Save changes and quit Vim. |
| `V` | Enter visual mode for selecting text. |
| `Ctrl + v` | Enter visual block mode for selecting columns of text. |
| `:s/old/new/g` | Replace "old" text with "new" in the current line. |
| `:%s/old/new/g` | Replace "old" text with "new" in the entire file. |
| `gg` | Move cursor to the beginning of the file. |
| `G` | Move cursor to the end of the file. |
| `Ctrl + d` | Scroll down half a screen. |
| `Ctrl + u` | Scroll up half a screen. |

#### **Navigation & Cursor Movement**
| Command | Description |
| ------- | ------------------------------------------------------------------ |
| `w` | Move cursor forward to the next word. |
| `b` | Move cursor backward to the previous word. |
| `e` | Move cursor to the end of the current word. |
| `{` | Move cursor to the beginning of the previous paragraph. |
| `}` | Move cursor to the beginning of the next paragraph. |
| `Ctrl + o` | Jump to the previous cursor position. |
| `Ctrl + i` | Jump to the next cursor position. |
| `H` | Move cursor to the top of the screen. |
| `M` | Move cursor to the middle of the screen. |
| `L` | Move cursor to the bottom of the screen. |

#### **Editing & Manipulating Text**

| Command | Description |
| ------- | ------------------------------------------------------------ |
| `J` | Join the current line with the next line. |
| `>>` | Indent the current line. Use `num>>` to indent multiple lines. |
| `<<` | Un-indent the current line. Use `num<<` to un-indent multiple lines. |
| `:set tabstop=4` | Change tab width to 4 spaces. |
| `:set expandtab` | Convert tabs to spaces automatically. |

#### **Searching & Replacing**

| Command | Description |
| ------- | ------------------------------------------------------------------ |
| `:%s/foo/bar/g` | Replace all occurrences of "foo" with "bar" in the entire document. |
| `:%s/foo/bar/gc` | Replace all occurrences but ask for confirmation before replacing. |
| `:%s/^/NEW /g` | Add "NEW" to the beginning of every line in the document. |
| `:%s/$/ END/g` | Add "END" to the end of every line in the document. |

#### **Working with Buffers & Windows**

| Command | Description |
| ------- | ----------------------------------------------- |
| `:e filename` | Open a new file. |
| `:tabnew filename` | Open a file in a new tab. |
| `gt` | Switch to the next tab. |
| `gT` | Switch to the previous tab. |
| `:vsp filename` | Open a file in a vertical split. |
| `:sp filename` | Open a file in a horizontal split. |
| `Ctrl + w w` | Switch between split windows. |
| `Ctrl + w q` | Close the current split window. |

#### **Clipboard & External File Interaction**

| Command | Description |
| ------- | ----------------------------------------------- |
| `:r filename` | Insert the contents of "filename" into the current buffer. |
| `:w filename` | Save the current buffer to "filename". |
| `"*y` | Yank (copy) text to the system clipboard. |
| `"*p` | Paste text from the system clipboard. |

## The .vimrc file

The `.vimrc` file is Vim's configuration file, allowing users to customize their editing experience by defining settings, key mappings, plugins, and behaviors. It’s essentially a way to tailor Vim to individual preferences, enabling automation, efficiency, and an improved workflow.  It is typically stored in the user's home directory alongside .bashrc, .profile, and other so-called "dot files".

### **Uses of `.vimrc`**

- **Customizing Settings:** Modify indentation, syntax highlighting, line numbering, and more.
- **Defining Shortcuts:** Set custom key mappings for repetitive tasks.
- **Enabling Plugins:** Load plugins to extend Vim’s functionality.
- **Optimizing Performance:** Adjust behavior for smoother operation, such as disabling swap files or tweaking search parameters.

### Example Configurations

Here are some common `.vimrc` customizations to enhance your Vim experience:

### **Basic Settings**

```vim
set number          " Show line numbers
set relativenumber  " Show relative line numbers
set cursorline      " Highlight the current line
set tabstop=4       " Set tab width to 4 spaces
set shiftwidth=4    " Indentation width
set expandtab       " Convert tabs to spaces
set autoindent      " Maintain indentation level
set nowrap          " Prevent line wrapping
```
- **Line Numbers:** `set number` displays absolute line numbers, while `set relativenumber` makes navigation easier by showing relative numbers.
- **Cursor Highlighting:** `set cursorline` makes it easy to see where your cursor is.
- **Indentation Control:** `tabstop`, `shiftwidth`, and `expandtab` ensure consistent spacing and indentation.
- **Autoindent:** Helps maintain indentation consistency when writing code.
- **Text Wrapping:** `set nowrap` prevents long lines from wrapping, keeping code readable.

### **Search & Navigation**

```vim
set ignorecase      " Ignore case in searches
set smartcase       " Override ignorecase if uppercase is used
set incsearch       " Highlight matches as you type
set hlsearch        " Highlight all search matches
```
- **Case Handling:** `ignorecase` makes searches case-insensitive, while `smartcase` ensures uppercase queries remain case-sensitive.
- **Incremental Search:** `incsearch` highlights matches as you type, providing instant feedback.
- **Highlighting Matches:** `hlsearch` ensures all found results are highlighted for better visibility.

### **Key Mappings**

```vim
nnoremap <leader>w :w<CR>  " Save file with <leader>w
nnoremap <leader>q :q<CR>  " Quit Vim with <leader>q
nnoremap <leader>x :x<CR>  " Save and exit with <leader>x
nnoremap <leader>n :bnext<CR>  " Move to next buffer
nnoremap <leader>p :bprevious<CR>  " Move to previous buffer
```
- **Leader Key Shortcuts:** These mappings allow quick execution of common tasks using a single key combination.
  - `<leader>w` saves the file.
  - `<leader>q` quits Vim.
  - `<leader>x` saves and quits.
  - `<leader>n` and `<leader>p` navigate buffers efficiently.

#### The Leader Key

In Vim, the **leader key** is a customizable key that serves as a prefix for user-defined shortcuts, making commands faster and more intuitive. By default, the leader key is set to `\` (backslash), but it can be changed to another key, such as the **comma** or **space**, to improve usability.

### **Why Use the Leader Key?**
- **Simplifies Commands:** Instead of typing long Vim commands, you can assign shortcuts to them.
- **Improves Speed:** Reduces keystrokes for common actions.
- **Personalized Workflow:** Tailor Vim to your habits and needs.

### **Setting a Custom Leader Key**
You can redefine the leader key in your `.vimrc` file:
```vim
let mapleader=","  " Set leader key to comma
```

### **Using the Leader Key**
Once defined, the leader key can be used to create custom shortcuts:
```vim
nnoremap <leader>w :w<CR>    " Save file with ,w
nnoremap <leader>q :q<CR>    " Quit Vim with ,q
nnoremap <leader>x :x<CR>    " Save and exit with ,x
```
This means pressing **`,` followed by `w`** will save the file instead of typing `:w<CR>` manually.

### **Plugins**

Vim plugins are add-ons that extend Vim’s functionality, providing features that aren’t available by default. They can enhance workflow, improve navigation, add syntax highlighting, and integrate with external tools. By leveraging plugins, Vim transforms into a highly customizable editor tailored to individual needs.

#### **Why Use Vim Plugins?**

- **Boost Efficiency:** Automate repetitive tasks and improve editing speed.
- **Enhance Navigation:** Plugins like FZF provide powerful search capabilities.
- **Improve UI & Aesthetics:** Status bar enhancements (e.g., Vim-Airline) make Vim more user-friendly.
- **Extend Language Support:** Syntax highlighting and auto-completion for various programming languages.
- **File Management:** Plugins like NERDTree simplify working with directories.

#### **Installing Plugins**

Installing and managing Vim plugins can be done using **plugin managers** or **native package management**.

#### **Using a Plugin Manager (Recommended)**

Popular plugin managers include:
- **vim-plug** – Simple and efficient.
- **Vundle** – Handles dependencies well.
- **Pathogen** – Organizes plugins neatly.

#### **Installing vim-plug**

Run this command to install vim-plug:

```sh
curl -fLo ~/.vim/autoload/plug.vim --create-dirs \
    https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim
```

#### **Adding Plugins**

Edit your `.vimrc` file:

```vim
call plug#begin('~/.vim/plugged')
Plug 'preservim/nerdtree'  " File explorer
Plug 'vim-airline/vim-airline'  " Status bar
Plug 'tpope/vim-surround'  " Surround text with quotes/brackets
Plug 'junegunn/fzf.vim'  " Fuzzy finder
call plug#end()
```

- **Plugin Management:** `plug#begin` and `plug#end` set up plugins using Vim-Plug.
  - **NERDTree:** Provides a file explorer.
  - **Vim-Airline:** Enhances the status bar with useful information.
  - **Vim-Surround:** Allows easy manipulation of surrounding characters.
  - **FZF:** Adds powerful fuzzy search capabilities.

Then, install plugins with:

```vim
:PlugInstall
```

#### **Managing Plugins**

- **Update plugins:** `:PlugUpdate`
- **Remove unused plugins:** `:PlugClean`
- **Check plugin status:** `:PlugStatus`

### **Native Plugin Management (Vim 8+)**

Vim 8 introduced **native package management**:

1. Create a plugin directory: `mkdir -p ~/.vim/pack/plugins/start`
2. Clone a plugin:  
   ```sh
   git clone https://github.com/preservim/nerdtree ~/.vim/pack/plugins/start/nerdtree
   ```
3. Restart Vim—plugin loads automatically.

Using a plugin manager is **easier** and **more scalable**, but native management works well for minimal setups.

### **Custom Status Line**

```vim
set laststatus=2
set statusline=%f\ %y\ %m\ %r\ %=Line:%l/%L\ Col:%c
```
- **Status Line Customization:** Displays the file name, type, modification status, and cursor position efficiently.

These configurations optimize Vim for usability, efficiency, and a better coding experience.

## Misc

* Learn vim: `vimtutor`
* [https://www.youtube.com/watch?v=OnUiHLYZgaA](https://www.youtube.com/watch?v=OnUiHLYZgaA)
* vim plugins: fuzzy finder plugin ctrlp /// surround.vim

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
