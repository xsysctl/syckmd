Local service is unauthenticated on fixed port (127.0.0.1:47653)
Any local process can potentially inject/poison suggestions.
(zsh/fish typically keep completion logic in-process.)

No quote-aware token acceptance
Word-accept logic is whitespace-based; quoted arguments can be broken.

No path-aware/tab-aware filesystem completion model
Suggestion engine doesn’t understand filesystem context like zsh completion does.

No fuzzy matching / typo correction
Tools like zsh (CORRECT + plugins), fish, and Fig/Warp can recover from near-miss input.

No contextual ranking by directory/session/toolchain
Modern tools prioritize by cwd/project; current ranking is simple recency/frequency-like behavior.

No interactive history search (Ctrl+R-style) with preview/filter
zsh + fzf/fish provide much stronger retrieval than linear up/down navigation.

some accessibility and ranking improvements are possible

speed and resource usage are not optimized yet
