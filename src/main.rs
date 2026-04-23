use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{self, Stdout, Write, stdout};
#[cfg(windows)]
use std::mem;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crossterm::cursor::{Hide, MoveToColumn, Show};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::queue;
use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
use crossterm::terminal::{Clear, ClearType, disable_raw_mode, enable_raw_mode};
use regex::{Regex, RegexBuilder};
use unicode_width::UnicodeWidthStr;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
#[cfg(windows)]
use windows_sys::Win32::System::Console::{
    GetConsoleCommandHistoryLengthW, GetConsoleCommandHistoryW,
};
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

#[derive(Clone, Copy, Eq, PartialEq)]
enum AcceptMode {
    Full,
    Word,
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[allow(dead_code)]
enum ShellKind {
    Cmd,
    PowerShell,
    Pwsh,
    Posix,
}

struct AppConfig {
    marker: &'static str,
    max_suggestions: usize,
}

struct ShellProfile {
    kind: ShellKind,
    program: String,
    command_args: Vec<String>,
}

struct EditorState {
    buffer: String,
    cursor_chars: usize,
}

struct TerminalGuard {
    stdout: Stdout,
}

impl EditorState {
    fn new() -> Self {
        Self {
            buffer: String::new(),
            cursor_chars: 0,
        }
    }

    fn char_len(&self) -> usize {
        self.buffer.chars().count()
    }

    fn cursor_byte_index(&self) -> usize {
        char_to_byte_index(&self.buffer, self.cursor_chars)
    }

    fn insert_char(&mut self, ch: char) {
        let byte = self.cursor_byte_index();
        self.buffer.insert(byte, ch);
        self.cursor_chars += 1;
    }

    fn insert_text(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        let byte = self.cursor_byte_index();
        self.buffer.insert_str(byte, text);
        self.cursor_chars += text.chars().count();
    }

    fn move_left(&mut self) {
        if self.cursor_chars > 0 {
            self.cursor_chars -= 1;
        }
    }

    fn move_right(&mut self) {
        if self.cursor_chars < self.char_len() {
            self.cursor_chars += 1;
        }
    }

    fn move_home(&mut self) {
        self.cursor_chars = 0;
    }

    fn move_end(&mut self) {
        self.cursor_chars = self.char_len();
    }

    fn backspace(&mut self) {
        if self.cursor_chars == 0 {
            return;
        }
        let start = char_to_byte_index(&self.buffer, self.cursor_chars - 1);
        let end = char_to_byte_index(&self.buffer, self.cursor_chars);
        self.buffer.replace_range(start..end, "");
        self.cursor_chars -= 1;
    }

    fn delete(&mut self) {
        if self.cursor_chars >= self.char_len() {
            return;
        }
        let start = char_to_byte_index(&self.buffer, self.cursor_chars);
        let end = char_to_byte_index(&self.buffer, self.cursor_chars + 1);
        self.buffer.replace_range(start..end, "");
    }

    fn left_and_right(&self) -> (&str, &str) {
        let cursor = self.cursor_byte_index();
        self.buffer.split_at(cursor)
    }

    fn clear(&mut self) {
        self.buffer.clear();
        self.cursor_chars = 0;
    }

    fn replace_buffer(&mut self, text: String) {
        self.buffer = text;
        self.cursor_chars = self.char_len();
    }
}

impl TerminalGuard {
    fn new() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = stdout();
        execute!(stdout, Hide)?;
        Ok(Self { stdout })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(self.stdout, ResetColor, Show, Print("\r\n"));
        let _ = disable_raw_mode();
    }
}

fn char_to_byte_index(text: &str, char_index: usize) -> usize {
    if char_index == 0 {
        return 0;
    }
    text.char_indices()
        .nth(char_index)
        .map_or(text.len(), |(idx, _)| idx)
}

#[cfg(windows)]
fn process_snapshot_table() -> HashMap<u32, (u32, String)> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return HashMap::new();
    }
    let mut entry = PROCESSENTRY32W {
        dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
        ..unsafe { mem::zeroed() }
    };
    let mut table = HashMap::new();
    if unsafe { Process32FirstW(snapshot, &mut entry) } != 0 {
        loop {
            let len = entry
                .szExeFile
                .iter()
                .position(|code| *code == 0)
                .unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
            table.insert(entry.th32ProcessID, (entry.th32ParentProcessID, name));
            if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }
    unsafe {
        CloseHandle(snapshot);
    }
    table
}

#[cfg(windows)]
fn detect_parent_shell_name() -> Option<String> {
    let table = process_snapshot_table();
    let current = unsafe { GetCurrentProcessId() };
    let mut pid = current;
    for _ in 0..32 {
        let (parent, _) = table.get(&pid)?.clone();
        if parent == 0 || parent == pid {
            break;
        }
        let (_, name) = table.get(&parent)?.clone();
        let lowered = name.to_ascii_lowercase();
        if lowered.contains("pwsh")
            || lowered.contains("powershell")
            || lowered.contains("cmd")
            || lowered.contains("bash")
            || lowered.contains("zsh")
            || lowered.contains("fish")
            || lowered.contains("sh")
        {
            return Some(lowered);
        }
        pid = parent;
    }
    None
}

fn detect_shell_profile() -> ShellProfile {
    #[cfg(windows)]
    {
        if let Some(parent) = detect_parent_shell_name() {
            if parent.contains("pwsh") {
                return ShellProfile {
                    kind: ShellKind::Pwsh,
                    program: "pwsh".to_owned(),
                    command_args: vec!["-NoLogo".to_owned(), "-Command".to_owned()],
                };
            }
            if parent.contains("powershell") {
                return ShellProfile {
                    kind: ShellKind::PowerShell,
                    program: "powershell".to_owned(),
                    command_args: vec!["-NoLogo".to_owned(), "-Command".to_owned()],
                };
            }
            if parent.contains("cmd") {
                return ShellProfile {
                    kind: ShellKind::Cmd,
                    program: env::var("ComSpec").unwrap_or_else(|_| "cmd".to_owned()),
                    command_args: vec!["/D".to_owned(), "/C".to_owned()],
                };
            }
        }
        return ShellProfile {
            kind: ShellKind::Cmd,
            program: env::var("ComSpec").unwrap_or_else(|_| "cmd".to_owned()),
            command_args: vec!["/D".to_owned(), "/C".to_owned()],
        };
    }
    #[cfg(not(windows))]
    {
        ShellProfile {
            kind: ShellKind::Posix,
            program: env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_owned()),
            command_args: vec!["-lc".to_owned()],
        }
    }
}

#[cfg(windows)]
fn utf16_null(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn load_console_history_for(exe: &str) -> Vec<String> {
    let exe_name = utf16_null(exe);
    let needed = unsafe { GetConsoleCommandHistoryLengthW(exe_name.as_ptr()) };
    if needed == 0 {
        return Vec::new();
    }
    let mut buffer = vec![0u16; needed as usize + 2];
    let copied = unsafe {
        GetConsoleCommandHistoryW(buffer.as_mut_ptr(), buffer.len() as u32, exe_name.as_ptr())
    };
    if copied == 0 {
        return Vec::new();
    }
    let mut entries = Vec::new();
    let mut start = 0usize;
    (0..copied as usize).for_each(|index| {
        if buffer[index] == 0 {
            if index > start {
                let value = String::from_utf16_lossy(&buffer[start..index]);
                let value = value.trim();
                if !value.is_empty() {
                    entries.push(value.to_owned());
                }
            }
            start = index + 1;
        }
    });
    entries
}

#[cfg(windows)]
fn load_cmd_history() -> Vec<String> {
    let mut seen = HashSet::new();
    let mut merged = Vec::new();
    ["cmd.exe", "syckmd.exe", "promptplus.exe"]
        .into_iter()
        .flat_map(load_console_history_for)
        .for_each(|entry| {
            if seen.insert(entry.clone()) {
                merged.push(entry);
            }
        });
    merged
}

#[cfg(not(windows))]
fn load_cmd_history() -> Vec<String> {
    Vec::new()
}

#[cfg(windows)]
fn load_powershell_history() -> Vec<String> {
    let appdata = env::var_os("APPDATA").map(PathBuf::from);
    let mut paths = Vec::new();
    if let Some(base) = appdata {
        paths.push(
            base.join("Microsoft")
                .join("Windows")
                .join("PowerShell")
                .join("PSReadLine")
                .join("ConsoleHost_history.txt"),
        );
        paths.push(
            base.join("Microsoft")
                .join("PowerShell")
                .join("PSReadLine")
                .join("ConsoleHost_history.txt"),
        );
    }
    let mut merged = Vec::new();
    let mut seen = HashSet::new();
    paths.into_iter().for_each(|path| {
        if let Ok(content) = fs::read_to_string(path) {
            content
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .for_each(|line| {
                    if seen.insert(line.to_owned()) {
                        merged.push(line.to_owned());
                    }
                });
        }
    });
    merged
}

#[cfg(not(windows))]
fn load_powershell_history() -> Vec<String> {
    Vec::new()
}

fn load_shell_history(shell: &ShellProfile) -> Vec<String> {
    #[cfg(windows)]
    {
        match shell.kind {
            ShellKind::PowerShell | ShellKind::Pwsh => load_powershell_history(),
            ShellKind::Cmd => load_cmd_history(),
            ShellKind::Posix => Vec::new(),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = shell;
        Vec::new()
    }
}

fn load_path_executables() -> Vec<String> {
    let mut seen = HashSet::new();
    let mut executables = Vec::new();
    let Some(path) = env::var_os("PATH") else {
        return executables;
    };
    for dir in env::split_paths(&path) {
        if executables.len() >= 12000 {
            break;
        }
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if executables.len() >= 12000 {
                break;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let lowered = name.to_ascii_lowercase();
            #[cfg(windows)]
            let normalized = if lowered.ends_with(".exe")
                || lowered.ends_with(".cmd")
                || lowered.ends_with(".bat")
                || lowered.ends_with(".com")
            {
                Path::new(&name)
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .map(str::to_owned)
            } else {
                None
            };
            #[cfg(not(windows))]
            let normalized = Some(name.clone());
            if let Some(value) = normalized {
                let key = value.to_ascii_lowercase();
                if seen.insert(key) {
                    executables.push(value);
                }
            }
        }
    }
    executables
}

fn prefers_path_completion(left: &str) -> bool {
    let mut parts = left.split_whitespace();
    let first = parts.next().unwrap_or_default().to_ascii_lowercase();
    let last = parts.next_back().unwrap_or_default();
    last.contains('\\')
        || last.contains('/')
        || [
            "cd", "type", "cat", "more", "del", "erase", "copy", "move", "start", "notepad",
            "code", "ls", "dir",
        ]
        .contains(&first.as_str())
}

fn fuzzy_score(query: &str, candidate: &str) -> Option<i64> {
    if query.is_empty() {
        return None;
    }
    if candidate.eq_ignore_ascii_case(query) {
        return None;
    }
    if candidate.starts_with(query) {
        return Some(20_000 - candidate.len() as i64);
    }
    let query_chars: Vec<char> = query.to_ascii_lowercase().chars().collect();
    let candidate_chars: Vec<char> = candidate.to_ascii_lowercase().chars().collect();
    let mut score = 0i64;
    let mut search_from = 0usize;
    let mut last = None::<usize>;
    for ch in query_chars {
        let found = (search_from..candidate_chars.len()).find(|idx| candidate_chars[*idx] == ch)?;
        score += 10;
        if let Some(previous) = last {
            if found == previous + 1 {
                score += 8;
            } else {
                score -= (found - previous) as i64;
            }
        }
        if found == 0
            || candidate_chars[found - 1].is_whitespace()
            || candidate_chars[found - 1] == '-'
        {
            score += 6;
        }
        last = Some(found);
        search_from = found + 1;
    }
    score -= (candidate_chars.len().saturating_sub(query.len())) as i64;
    Some(score)
}

fn build_query_regex(query: &str) -> Option<Regex> {
    (!query.trim().is_empty() && query.len() <= 96)
        .then_some(query)
        .and_then(|value| RegexBuilder::new(value).case_insensitive(true).build().ok())
}

fn split_last_token(text: &str) -> (&str, &str) {
    let split = text
        .char_indices()
        .rev()
        .find_map(|(idx, ch)| ch.is_whitespace().then_some(idx + ch.len_utf8()))
        .unwrap_or(0);
    text.split_at(split)
}

fn shell_builtin_candidates(shell_kind: ShellKind) -> &'static [&'static str] {
    match shell_kind {
        ShellKind::Cmd => &[
            "assoc", "call", "cd", "chdir", "cls", "copy", "date", "del", "dir", "echo",
            "endlocal", "erase", "for", "ftype", "if", "md", "mkdir", "mklink", "move", "path",
            "popd", "prompt", "pushd", "ren", "rename", "rd", "rmdir", "set", "setlocal", "shift",
            "start", "time", "title", "type", "ver", "verify", "vol", "where", "find", "findstr",
            "tasklist", "taskkill", "wmic",
        ],
        ShellKind::PowerShell | ShellKind::Pwsh => &[
            "Get-ChildItem",
            "Set-Location",
            "Copy-Item",
            "Move-Item",
            "Remove-Item",
            "Get-Content",
            "Set-Content",
            "Add-Content",
            "Select-String",
            "Get-Process",
            "Stop-Process",
            "Get-Service",
            "Start-Service",
            "Stop-Service",
            "Restart-Service",
            "Get-Command",
            "Get-Help",
            "Where-Object",
            "ForEach-Object",
            "Sort-Object",
            "Measure-Object",
            "Select-Object",
            "New-Item",
            "Test-Path",
            "Resolve-Path",
            "Start-Process",
            "Write-Host",
            "Write-Output",
            "Clear-Host",
        ],
        ShellKind::Posix => &[
            "cd", "ls", "cp", "mv", "rm", "cat", "grep", "find", "awk", "sed", "pwd", "echo",
            "touch", "mkdir", "rmdir", "chmod", "chown", "which", "whereis",
        ],
    }
}

fn filesystem_candidates(
    line_prefix: &str,
    path_fragment: &str,
    cwd: &Path,
    limit: usize,
) -> Vec<String> {
    if path_fragment.starts_with('-') {
        return Vec::new();
    }
    let quote = path_fragment
        .chars()
        .next()
        .filter(|ch| *ch == '"' || *ch == '\'');
    let cleaned = path_fragment.trim_matches('"').trim_matches('\'');
    let path = PathBuf::from(cleaned);
    let prefix = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    let path_has_dir = cleaned.contains('\\') || cleaned.contains('/') || path.is_absolute();
    let dir = if path.is_absolute() {
        path.parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| cwd.to_path_buf())
    } else if path_has_dir {
        cwd.join(path.parent().unwrap_or(Path::new("")))
    } else {
        cwd.to_path_buf()
    };
    if !dir.is_dir() {
        return Vec::new();
    }
    let separator = if cleaned.contains('/') { '/' } else { '\\' };
    let parent_prefix = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .map(|value| format!("{}{}", value.display(), separator))
        .unwrap_or_default();
    let render_prefix = if line_prefix.is_empty() {
        String::new()
    } else if line_prefix.chars().last().is_some_and(char::is_whitespace) {
        line_prefix.to_owned()
    } else {
        format!("{line_prefix} ")
    };
    let mut values = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return values;
    };
    for entry in entries.flatten() {
        if values.len() >= limit {
            break;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !prefix.is_empty() && fuzzy_score(prefix, &name).is_none() {
            continue;
        }
        let token_value = format!("{parent_prefix}{name}");
        let token_value = quote.map_or(token_value.clone(), |ch| format!("{ch}{token_value}"));
        values.push(format!("{render_prefix}{token_value}"));
    }
    values
}

fn word_chunk(text: &str) -> String {
    let whitespace_len = text
        .char_indices()
        .find_map(|(idx, ch)| (!ch.is_whitespace()).then_some(idx))
        .unwrap_or(text.len());
    let rest = &text[whitespace_len..];
    let token_len = rest
        .char_indices()
        .find_map(|(idx, ch)| ch.is_whitespace().then_some(idx))
        .unwrap_or(rest.len());
    format!("{}{}", &text[..whitespace_len], &rest[..token_len])
}

fn candidate_insert_segment(left: &str, right: &str, candidate: &str) -> Option<String> {
    let tail = candidate.strip_prefix(left)?;
    if right.is_empty() {
        return Some(tail.to_owned());
    }
    tail.find(right)
        .map(|index| tail[..index].to_owned())
        .or_else(|| Some(tail.to_owned()))
}

fn candidate_rank(
    left: &str,
    right: &str,
    token_query: &str,
    token_regex: Option<&Regex>,
    candidate: &str,
) -> Option<i64> {
    let insert = candidate_insert_segment(left, right, candidate)?;
    if insert.is_empty() && candidate == format!("{left}{right}") {
        return None;
    }
    let mut score = 12_000 - insert.len() as i64;
    if !right.is_empty() {
        if let Some(position) = candidate[left.len()..].find(right) {
            score += 3_000 - (position as i64 * 4);
        } else {
            score += 800;
        }
    }
    if token_query.is_empty() {
        return Some(score);
    }
    let mut matched = false;
    if let Some(fuzzy) = fuzzy_score(token_query, candidate) {
        score += fuzzy;
        matched = true;
    }
    if let Some(regex) = token_regex {
        if regex.is_match(candidate) {
            score += 1_700;
            matched = true;
        }
    }
    if candidate
        .to_ascii_lowercase()
        .contains(&token_query.to_ascii_lowercase())
    {
        score += 700;
        matched = true;
    }
    matched.then_some(score)
}

fn suggestion_for_editor(
    editor: &EditorState,
    cwd: &Path,
    history: &[String],
    executables: &[String],
    max_suggestions: usize,
    shell_kind: ShellKind,
) -> Vec<String> {
    let (left, right) = editor.left_and_right();
    if left.trim().is_empty() && right.trim().is_empty() {
        return Vec::new();
    }
    let (line_prefix, token_fragment) = split_last_token(left);
    let token_query = token_fragment.trim_matches('"').trim_matches('\'');
    let token_regex = build_query_regex(token_query);
    let mut ranked = HashMap::<String, i64>::new();
    history
        .iter()
        .rev()
        .take(3000)
        .enumerate()
        .for_each(|(idx, line)| {
            if let Some(score) =
                candidate_rank(left, right, token_query, token_regex.as_ref(), line)
            {
                let rank = score + 7_000 - idx as i64;
                ranked
                    .entry(line.clone())
                    .and_modify(|value| *value = (*value).max(rank))
                    .or_insert(rank);
            }
        });
    shell_builtin_candidates(shell_kind)
        .iter()
        .for_each(|candidate| {
            if let Some(score) =
                candidate_rank(left, right, token_query, token_regex.as_ref(), candidate)
            {
                ranked
                    .entry((*candidate).to_owned())
                    .and_modify(|value| *value = (*value).max(score + 7_500))
                    .or_insert(score + 7_500);
            }
        });
    if !left.chars().any(|ch| ch.is_whitespace()) && !right.chars().any(|ch| ch.is_whitespace()) {
        executables.iter().take(8000).for_each(|exe| {
            if let Some(score) = candidate_rank(left, right, token_query, token_regex.as_ref(), exe)
            {
                let rank = score + 5_000;
                ranked
                    .entry(exe.clone())
                    .and_modify(|value| *value = (*value).max(rank))
                    .or_insert(rank);
            }
        });
    }

    let should_show_files = left.chars().any(|ch| ch.is_whitespace()) || token_fragment.is_empty();
    if should_show_files {
        let file_line_prefix = line_prefix;
        let file_token_fragment = token_fragment;
        let file_regex = build_query_regex(file_token_fragment);
        filesystem_candidates(
            file_line_prefix,
            file_token_fragment,
            cwd,
            max_suggestions.saturating_mul(5),
        )
        .into_iter()
        .for_each(|candidate| {
            if let Some(score) = candidate_rank(
                left,
                right,
                file_token_fragment,
                file_regex.as_ref(),
                &candidate,
            ) {
                let rank = score
                    + if prefers_path_completion(left) {
                        11_000
                    } else {
                        7_000
                    };
                ranked
                    .entry(candidate)
                    .and_modify(|value| *value = (*value).max(rank))
                    .or_insert(rank);
            }
        });
    }
    let mut values: Vec<(String, i64)> = ranked.into_iter().collect();
    values.sort_by(|(left_text, left_score), (right_text, right_score)| {
        right_score
            .cmp(left_score)
            .then_with(|| left_text.len().cmp(&right_text.len()))
            .then_with(|| {
                left_text
                    .to_ascii_lowercase()
                    .cmp(&right_text.to_ascii_lowercase())
            })
    });
    values
        .into_iter()
        .take(max_suggestions)
        .map(|(text, _)| text)
        .collect()
}

fn selected_suggestion_suffix(
    editor: &EditorState,
    suggestions: &[String],
    selected_index: usize,
) -> Option<String> {
    let candidate = suggestions.get(selected_index)?;
    let (left, right) = editor.left_and_right();
    candidate_insert_segment(left, right, candidate).filter(|value| !value.is_empty())
}

fn accept_ranked_suggestion(
    editor: &mut EditorState,
    suggestions: &[String],
    selected_index: usize,
    mode: AcceptMode,
) {
    let Some(selected) = suggestions.get(selected_index) else {
        return;
    };
    let (left, right) = {
        let (left, right) = editor.left_and_right();
        (left.to_owned(), right.to_owned())
    };
    if let Some(suffix) = candidate_insert_segment(&left, &right, selected) {
        let piece = if mode == AcceptMode::Full {
            suffix
        } else {
            word_chunk(&suffix)
        };
        editor.insert_text(&piece);
        return;
    }
    editor.replace_buffer(selected.clone());
}

fn is_exit_command(command: &str) -> bool {
    let mut parts = command.split_whitespace();
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(name), Some(flag), None)
            if name.eq_ignore_ascii_case("syckmd") && flag.eq_ignore_ascii_case("--exit")
    )
}

fn display_path(path: &Path) -> String {
    let text = path.display().to_string();
    #[cfg(windows)]
    {
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{rest}");
        }
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            return rest.to_owned();
        }
    }
    text
}

fn shell_prompt(shell: &ShellProfile, cwd: &Path) -> String {
    match shell.kind {
        ShellKind::Cmd => format!("{}>", display_path(cwd)),
        ShellKind::PowerShell | ShellKind::Pwsh => format!("PS {}>", display_path(cwd)),
        ShellKind::Posix => format!("{}$ ", display_path(cwd)),
    }
}

fn render(
    stdout: &mut Stdout,
    prompt: &str,
    config: &AppConfig,
    editor: &EditorState,
    suggestion: Option<&str>,
    suggestions: &[String],
    selected_index: usize,
) -> io::Result<()> {
    use crossterm::cursor::{MoveToNextLine, RestorePosition, SavePosition};
    let (left, right) = editor.left_and_right();
    queue!(
        stdout,
        MoveToColumn(0),
        Clear(ClearType::CurrentLine),
        Print(prompt),
        Print(left)
    )?;
    if let Some(ghost) = suggestion {
        queue!(
            stdout,
            SetForegroundColor(Color::DarkGrey),
            Print(config.marker),
            Print(ghost),
            ResetColor
        )?;
    }
    queue!(stdout, Print(right))?;
    let cursor_col = UnicodeWidthStr::width(prompt) + UnicodeWidthStr::width(left);
    queue!(
        stdout,
        MoveToColumn(cursor_col as u16),
        SavePosition,
        MoveToNextLine(1),
        MoveToColumn(0),
        Clear(ClearType::FromCursorDown)
    )?;
    suggestions.iter().enumerate().for_each(|(index, text)| {
        let _ = queue!(
            stdout,
            MoveToNextLine(1),
            MoveToColumn(0),
            Clear(ClearType::CurrentLine),
            SetForegroundColor(if index == selected_index {
                Color::DarkYellow
            } else {
                Color::DarkGrey
            }),
            Print(format!("{} {}", index + 1, text)),
            ResetColor
        );
    });
    queue!(stdout, RestorePosition)?;
    stdout.flush()
}

fn print_entered_line(stdout: &mut Stdout, prompt: &str, line: &str) -> io::Result<()> {
    queue!(
        stdout,
        MoveToColumn(0),
        Clear(ClearType::CurrentLine),
        Print(prompt),
        Print(line),
        Print("\r\n")
    )?;
    stdout.flush()
}

fn is_ctrl_tab(event: &KeyEvent) -> bool {
    event.code == KeyCode::Tab && event.modifiers.contains(KeyModifiers::CONTROL)
}

fn is_ctrl_right(event: &KeyEvent) -> bool {
    event.code == KeyCode::Right && event.modifiers.contains(KeyModifiers::CONTROL)
}

fn run_command(
    stdout: &mut Stdout,
    command: &str,
    cwd: &Path,
    shell: &ShellProfile,
) -> io::Result<()> {
    stdout.flush()?;
    disable_raw_mode()?;
    execute!(stdout, Show)?;
    let mut process = Command::new(&shell.program);
    shell.command_args.iter().for_each(|arg| {
        process.arg(arg);
    });
    let status = process
        .arg(command)
        .current_dir(cwd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status();
    execute!(stdout, Hide)?;
    enable_raw_mode()?;
    status.map(|_| ())
}

fn handle_cd(stdout: &mut Stdout, command: &str, cwd: &mut PathBuf) -> io::Result<bool> {
    let trimmed = command.trim();
    if !trimmed.to_ascii_lowercase().starts_with("cd") {
        return Ok(false);
    }
    if trimmed.len() > 2 {
        let marker = trimmed.chars().nth(2).unwrap_or_default();
        if !(marker.is_whitespace()
            || marker == '.'
            || marker == '\\'
            || marker == '/'
            || marker == '"')
        {
            return Ok(false);
        }
    }
    let mut remainder = trimmed.get(2..).unwrap_or("").trim_start();
    if remainder.len() >= 2 && remainder[..2].eq_ignore_ascii_case("/d") {
        remainder = remainder[2..].trim_start();
    }
    if remainder.is_empty() {
        queue!(stdout, Print(format!("{}\r\n", display_path(cwd))))?;
        stdout.flush()?;
        return Ok(true);
    }
    let target = remainder.trim().trim_matches('"');
    let next = {
        let raw = PathBuf::from(target);
        if raw.is_absolute() {
            raw
        } else {
            cwd.join(raw)
        }
    };
    if next.is_dir() {
        *cwd = next.canonicalize().unwrap_or(next);
    } else {
        queue!(
            stdout,
            Print("The system cannot find the path specified.\r\n")
        )?;
        stdout.flush()?;
    }
    Ok(true)
}

fn apply_history_entry(
    editor: &mut EditorState,
    history: &[String],
    history_index: &mut Option<usize>,
    history_draft: &mut String,
    move_up: bool,
) {
    if history.is_empty() {
        return;
    }
    if move_up {
        match history_index {
            None => {
                *history_draft = editor.buffer.clone();
                *history_index = Some(history.len() - 1);
            }
            Some(index) => {
                *history_index = Some(index.saturating_sub(1));
            }
        }
        if let Some(index) = history_index {
            editor.replace_buffer(history[*index].clone());
        }
        return;
    }
    match history_index {
        None => {}
        Some(index) if *index + 1 < history.len() => {
            *history_index = Some(*index + 1);
            if let Some(next_index) = history_index {
                editor.replace_buffer(history[*next_index].clone());
            }
        }
        Some(_) => {
            *history_index = None;
            editor.replace_buffer(history_draft.clone());
        }
    }
}

fn detach_history(history_index: &mut Option<usize>) {
    if history_index.is_some() {
        *history_index = None;
    }
}

fn run_shell(config: &AppConfig) -> io::Result<()> {
    let shell = detect_shell_profile();
    let mut terminal = TerminalGuard::new()?;
    let mut editor = EditorState::new();
    let mut cwd = env::current_dir()?;
    let mut history = load_shell_history(&shell);
    let executables = load_path_executables();
    let mut history_index = None::<usize>;
    let mut history_draft = String::new();
    let mut suggestion_index = 0usize;
    let mut suggestion_nav = false;

    loop {
        let prompt = shell_prompt(&shell, &cwd);
        let suggestions = if history_index.is_some() {
            Vec::new()
        } else {
            suggestion_for_editor(
                &editor,
                &cwd,
                &history,
                &executables,
                config.max_suggestions,
                shell.kind,
            )
        };
        if suggestions.is_empty() {
            suggestion_nav = false;
            suggestion_index = 0;
        } else if !suggestion_nav {
            suggestion_index = 0;
        } else if suggestion_index >= suggestions.len() {
            suggestion_index = suggestions.len().saturating_sub(1);
        }
        let top_suffix = selected_suggestion_suffix(&editor, &suggestions, suggestion_index);
        render(
            &mut terminal.stdout,
            &prompt,
            config,
            &editor,
            top_suffix.as_deref(),
            &suggestions,
            suggestion_index,
        )?;
        match event::read()? {
            Event::Key(key_event) if key_event.kind == KeyEventKind::Press => {
                if key_event.code == KeyCode::Tab {
                    if is_ctrl_tab(&key_event) {
                        accept_ranked_suggestion(
                            &mut editor,
                            &suggestions,
                            suggestion_index,
                            AcceptMode::Word,
                        );
                    } else {
                        accept_ranked_suggestion(
                            &mut editor,
                            &suggestions,
                            suggestion_index,
                            AcceptMode::Full,
                        );
                    }
                    continue;
                }
                if is_ctrl_right(&key_event) {
                    accept_ranked_suggestion(
                        &mut editor,
                        &suggestions,
                        suggestion_index,
                        AcceptMode::Word,
                    );
                    continue;
                }
                match key_event.code {
                    KeyCode::Char('c') if key_event.modifiers.contains(KeyModifiers::CONTROL) => {
                        let line = editor.buffer.clone();
                        editor.clear();
                        history_index = None;
                        history_draft.clear();
                        queue!(
                            terminal.stdout,
                            MoveToColumn(0),
                            Clear(ClearType::CurrentLine),
                            Print(prompt.as_str()),
                            Print(line),
                            Print("^C\r\n")
                        )?;
                        terminal.stdout.flush()?;
                    }
                    KeyCode::Char(ch)
                        if key_event.modifiers.is_empty()
                            || key_event.modifiers == KeyModifiers::SHIFT =>
                    {
                        detach_history(&mut history_index);
                        suggestion_nav = false;
                        suggestion_index = 0;
                        editor.insert_char(ch);
                    }
                    KeyCode::Backspace => {
                        detach_history(&mut history_index);
                        suggestion_nav = false;
                        suggestion_index = 0;
                        editor.backspace();
                    }
                    KeyCode::Delete => {
                        detach_history(&mut history_index);
                        suggestion_nav = false;
                        suggestion_index = 0;
                        editor.delete();
                    }
                    KeyCode::Left => {
                        if history_index.is_some() {
                            detach_history(&mut history_index);
                        }
                        suggestion_nav = false;
                        suggestion_index = 0;
                        editor.move_left();
                    }
                    KeyCode::Right => {
                        if history_index.is_some() {
                            detach_history(&mut history_index);
                        }
                        suggestion_nav = false;
                        suggestion_index = 0;
                        editor.move_right();
                    }
                    KeyCode::Home => {
                        if history_index.is_some() {
                            detach_history(&mut history_index);
                        }
                        suggestion_nav = false;
                        suggestion_index = 0;
                        editor.move_home();
                    }
                    KeyCode::End => {
                        if history_index.is_some() {
                            detach_history(&mut history_index);
                        }
                        suggestion_nav = false;
                        suggestion_index = 0;
                        editor.move_end();
                    }
                    KeyCode::Up => {
                        if suggestion_nav && !suggestions.is_empty() {
                            if suggestion_index > 0 {
                                suggestion_index -= 1;
                            } else {
                                suggestion_nav = false;
                                apply_history_entry(
                                    &mut editor,
                                    &history,
                                    &mut history_index,
                                    &mut history_draft,
                                    true,
                                );
                            }
                            continue;
                        }
                        apply_history_entry(
                            &mut editor,
                            &history,
                            &mut history_index,
                            &mut history_draft,
                            true,
                        );
                    }
                    KeyCode::Down => {
                        if history_index.is_some() {
                            apply_history_entry(
                                &mut editor,
                                &history,
                                &mut history_index,
                                &mut history_draft,
                                false,
                            );
                            continue;
                        }
                        if suggestions.is_empty() {
                            continue;
                        }
                        if !suggestion_nav {
                            suggestion_nav = true;
                            suggestion_index = if suggestions.len() > 1 { 1 } else { 0 };
                        } else if suggestion_index + 1 < suggestions.len() {
                            suggestion_index += 1;
                        }
                    }
                    KeyCode::Enter => {
                        let entered_line = editor.buffer.clone();
                        let entered = entered_line.trim_end().to_owned();
                        print_entered_line(&mut terminal.stdout, &prompt, &entered_line)?;
                        editor.clear();
                        if entered.is_empty() {
                            continue;
                        }
                        if history.last().map(String::as_str) != Some(entered.as_str()) {
                            history.push(entered.clone());
                        }
                        history_index = None;
                        history_draft.clear();
                        suggestion_nav = false;
                        suggestion_index = 0;
                        if is_exit_command(&entered) {
                            break;
                        }
                        if !handle_cd(&mut terminal.stdout, &entered, &mut cwd)? {
                            let _ = run_command(&mut terminal.stdout, &entered, &cwd, &shell);
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn main() {
    let _ = dotenvy::dotenv();
    let max_suggestions = env::var("SYCKMD_MAX_SUGGESTIONS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .map(|value| value.clamp(1, 50))
        .unwrap_or(10);
    let config = AppConfig {
        marker: "",
        max_suggestions,
    };
    let result = run_shell(&config);
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
