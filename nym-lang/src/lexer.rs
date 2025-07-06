//! NymScript Lexer - Week 61-62
//! 
//! This module implements lexical analysis for NymScript source code

use crate::error::{NymScriptError, ErrorType, ErrorSeverity, SourceLocation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// NymScript lexer
pub struct NymScriptLexer {
    /// Source code
    source: String,
    /// Current position
    position: usize,
    /// Current line
    line: u32,
    /// Current column
    column: u32,
    /// Keywords map
    keywords: HashMap<String, TokenType>,
}

/// Token produced by lexer
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Token {
    /// Token type
    pub token_type: TokenType,
    /// Token value (for literals and identifiers)
    pub value: String,
    /// Source location
    pub location: SourceLocation,
}

/// Token types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TokenType {
    // Literals
    Integer,
    Float,
    String,
    Boolean,
    Null,
    
    // Identifiers and keywords
    Identifier,
    
    // Keywords
    Contract,
    Function,
    Let,
    Mut,
    If,
    Else,
    While,
    For,
    In,
    Return,
    Break,
    Continue,
    Match,
    True,
    False,
    Null_,
    
    // Privacy keywords
    Private,
    Public,
    Confidential,
    Secret,
    Anonymous,
    
    // Security keywords
    Secure,
    Trusted,
    Verified,
    
    // Cryptographic keywords
    Encrypt,
    Decrypt,
    Proof,
    Verify,
    Commit,
    Reveal,
    Hash,
    Sign,
    
    // Type keywords
    Bool,
    Int,
    UInt,
    Field,
    String_,
    Bytes,
    Address,
    Array,
    
    // Operators
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    And,
    Or,
    Not,
    Assign,
    PlusAssign,
    MinusAssign,
    StarAssign,
    SlashAssign,
    
    // Privacy operators
    PrivateAdd,
    PrivateMul,
    PrivateEq,
    CryptoAdd,
    CryptoMul,
    
    // Punctuation
    LeftParen,
    RightParen,
    LeftBrace,
    RightBrace,
    LeftBracket,
    RightBracket,
    Comma,
    Semicolon,
    Colon,
    DoubleColon,
    Dot,
    Arrow,
    FatArrow,
    Question,
    At,
    
    // Privacy annotations
    PrivacyLevel,
    SecurityLevel,
    
    // Privacy-specific tokens
    PrivacyLevel_(String), // @private, @public, etc.
    SecurityLevel_(String), // @secure, @trusted, etc.
    ZKCircuit, // circuit
    ZKWitness, // witness
    ZKProof_, // proof (different from Proof keyword)
    
    // Macro and meta programming
    Macro,
    Include,
    Module,
    Use,
    Import,
    Export,
    
    // Special
    Newline,
    Whitespace,
    Comment,
    EOF,
}

/// Lexer error
#[derive(Debug, Clone)]
pub struct LexerError {
    /// Error message
    pub message: String,
    /// Error location
    pub location: SourceLocation,
}

impl NymScriptLexer {
    /// Create new lexer
    pub fn new(source: &str) -> Self {
        let mut keywords = HashMap::new();
        
        // Language keywords
        keywords.insert("contract".to_string(), TokenType::Contract);
        keywords.insert("fn".to_string(), TokenType::Function);
        keywords.insert("let".to_string(), TokenType::Let);
        keywords.insert("mut".to_string(), TokenType::Mut);
        keywords.insert("if".to_string(), TokenType::If);
        keywords.insert("else".to_string(), TokenType::Else);
        keywords.insert("while".to_string(), TokenType::While);
        keywords.insert("for".to_string(), TokenType::For);
        keywords.insert("in".to_string(), TokenType::In);
        keywords.insert("return".to_string(), TokenType::Return);
        keywords.insert("break".to_string(), TokenType::Break);
        keywords.insert("continue".to_string(), TokenType::Continue);
        keywords.insert("match".to_string(), TokenType::Match);
        keywords.insert("true".to_string(), TokenType::True);
        keywords.insert("false".to_string(), TokenType::False);
        keywords.insert("null".to_string(), TokenType::Null_);
        
        // Privacy keywords
        keywords.insert("private".to_string(), TokenType::Private);
        keywords.insert("public".to_string(), TokenType::Public);
        keywords.insert("confidential".to_string(), TokenType::Confidential);
        keywords.insert("secret".to_string(), TokenType::Secret);
        keywords.insert("anonymous".to_string(), TokenType::Anonymous);
        
        // Security keywords
        keywords.insert("secure".to_string(), TokenType::Secure);
        keywords.insert("trusted".to_string(), TokenType::Trusted);
        keywords.insert("verified".to_string(), TokenType::Verified);
        
        // Cryptographic keywords
        keywords.insert("encrypt".to_string(), TokenType::Encrypt);
        keywords.insert("decrypt".to_string(), TokenType::Decrypt);
        keywords.insert("proof".to_string(), TokenType::Proof);
        keywords.insert("verify".to_string(), TokenType::Verify);
        keywords.insert("commit".to_string(), TokenType::Commit);
        keywords.insert("reveal".to_string(), TokenType::Reveal);
        keywords.insert("hash".to_string(), TokenType::Hash);
        keywords.insert("sign".to_string(), TokenType::Sign);
        
        // Type keywords
        keywords.insert("bool".to_string(), TokenType::Bool);
        keywords.insert("int".to_string(), TokenType::Int);
        keywords.insert("uint".to_string(), TokenType::UInt);
        keywords.insert("field".to_string(), TokenType::Field);
        keywords.insert("string".to_string(), TokenType::String_);
        keywords.insert("bytes".to_string(), TokenType::Bytes);
        keywords.insert("address".to_string(), TokenType::Address);
        keywords.insert("array".to_string(), TokenType::Array);
        
        // Macro and meta programming
        keywords.insert("macro".to_string(), TokenType::Macro);
        keywords.insert("include".to_string(), TokenType::Include);
        keywords.insert("module".to_string(), TokenType::Module);
        keywords.insert("use".to_string(), TokenType::Use);
        keywords.insert("import".to_string(), TokenType::Import);
        keywords.insert("export".to_string(), TokenType::Export);
        
        // Additional privacy keywords
        keywords.insert("circuit".to_string(), TokenType::ZKCircuit);
        keywords.insert("witness".to_string(), TokenType::ZKWitness);
        
        Self {
            source: source.to_string(),
            position: 0,
            line: 1,
            column: 1,
            keywords,
        }
    }

    /// Tokenize the entire source
    pub fn tokenize(&mut self) -> Result<Vec<Token>, Vec<LexerError>> {
        let mut tokens = Vec::new();
        let mut errors = Vec::new();

        while !self.is_at_end() {
            match self.scan_token() {
                Ok(Some(token)) => {
                    // Skip whitespace and comments for most parsing
                    if !matches!(token.token_type, TokenType::Whitespace | TokenType::Comment) {
                        tokens.push(token);
                    }
                }
                Ok(None) => {
                    // Token was consumed but no token produced (whitespace)
                }
                Err(error) => {
                    errors.push(error);
                    // Try to recover by advancing one character
                    self.advance();
                }
            }
        }

        // Add EOF token
        tokens.push(Token {
            token_type: TokenType::EOF,
            value: String::new(),
            location: self.current_location(),
        });

        if errors.is_empty() {
            Ok(tokens)
        } else {
            Err(errors)
        }
    }

    /// Scan a single token
    fn scan_token(&mut self) -> Result<Option<Token>, LexerError> {
        let start_location = self.current_location();
        let ch = self.advance();

        match ch {
            ' ' | '\r' | '\t' => {
                self.skip_whitespace();
                Ok(Some(Token {
                    token_type: TokenType::Whitespace,
                    value: " ".to_string(),
                    location: start_location,
                }))
            }
            '\n' => {
                self.line += 1;
                self.column = 1;
                Ok(Some(Token {
                    token_type: TokenType::Newline,
                    value: "\n".to_string(),
                    location: start_location,
                }))
            }
            '/' => {
                if self.match_char('/') {
                    // Line comment
                    let comment = self.scan_line_comment();
                    Ok(Some(Token {
                        token_type: TokenType::Comment,
                        value: comment,
                        location: start_location,
                    }))
                } else if self.match_char('*') {
                    // Block comment
                    let comment = self.scan_block_comment()?;
                    Ok(Some(Token {
                        token_type: TokenType::Comment,
                        value: comment,
                        location: start_location,
                    }))
                } else if self.match_char('=') {
                    Ok(Some(Token {
                        token_type: TokenType::SlashAssign,
                        value: "/=".to_string(),
                        location: start_location,
                    }))
                } else {
                    Ok(Some(Token {
                        token_type: TokenType::Slash,
                        value: "/".to_string(),
                        location: start_location,
                    }))
                }
            }
            '+' => {
                if self.match_char('=') {
                    Ok(Some(Token {
                        token_type: TokenType::PlusAssign,
                        value: "+=".to_string(),
                        location: start_location,
                    }))
                } else if self.match_char('+') && self.match_char('=') {
                    // Private addition operator +=
                    Ok(Some(Token {
                        token_type: TokenType::PrivateAdd,
                        value: "++=".to_string(),
                        location: start_location,
                    }))
                } else {
                    Ok(Some(Token {
                        token_type: TokenType::Plus,
                        value: "+".to_string(),
                        location: start_location,
                    }))
                }
            }
            '-' => {
                if self.match_char('=') {
                    Ok(Some(Token {
                        token_type: TokenType::MinusAssign,
                        value: "-=".to_string(),
                        location: start_location,
                    }))
                } else if self.match_char('>') {
                    Ok(Some(Token {
                        token_type: TokenType::Arrow,
                        value: "->".to_string(),
                        location: start_location,
                    }))
                } else {
                    Ok(Some(Token {
                        token_type: TokenType::Minus,
                        value: "-".to_string(),
                        location: start_location,
                    }))
                }
            }
            '*' => {
                if self.match_char('=') {
                    Ok(Some(Token {
                        token_type: TokenType::StarAssign,
                        value: "*=".to_string(),
                        location: start_location,
                    }))
                } else if self.match_char('*') && self.match_char('=') {
                    // Private multiplication operator **=
                    Ok(Some(Token {
                        token_type: TokenType::PrivateMul,
                        value: "**=".to_string(),
                        location: start_location,
                    }))
                } else {
                    Ok(Some(Token {
                        token_type: TokenType::Star,
                        value: "*".to_string(),
                        location: start_location,
                    }))
                }
            }
            '%' => Ok(Some(Token {
                token_type: TokenType::Percent,
                value: "%".to_string(),
                location: start_location,
            })),
            '=' => {
                if self.match_char('=') {
                    if self.match_char('=') {
                        // Private equality operator ===
                        Ok(Some(Token {
                            token_type: TokenType::PrivateEq,
                            value: "===".to_string(),
                            location: start_location,
                        }))
                    } else {
                        Ok(Some(Token {
                            token_type: TokenType::Equal,
                            value: "==".to_string(),
                            location: start_location,
                        }))
                    }
                } else if self.match_char('>') {
                    Ok(Some(Token {
                        token_type: TokenType::FatArrow,
                        value: "=>".to_string(),
                        location: start_location,
                    }))
                } else {
                    Ok(Some(Token {
                        token_type: TokenType::Assign,
                        value: "=".to_string(),
                        location: start_location,
                    }))
                }
            }
            '!' => {
                if self.match_char('=') {
                    Ok(Some(Token {
                        token_type: TokenType::NotEqual,
                        value: "!=".to_string(),
                        location: start_location,
                    }))
                } else {
                    Ok(Some(Token {
                        token_type: TokenType::Not,
                        value: "!".to_string(),
                        location: start_location,
                    }))
                }
            }
            '<' => {
                if self.match_char('=') {
                    Ok(Some(Token {
                        token_type: TokenType::LessEqual,
                        value: "<=".to_string(),
                        location: start_location,
                    }))
                } else {
                    Ok(Some(Token {
                        token_type: TokenType::Less,
                        value: "<".to_string(),
                        location: start_location,
                    }))
                }
            }
            '>' => {
                if self.match_char('=') {
                    Ok(Some(Token {
                        token_type: TokenType::GreaterEqual,
                        value: ">=".to_string(),
                        location: start_location,
                    }))
                } else {
                    Ok(Some(Token {
                        token_type: TokenType::Greater,
                        value: ">".to_string(),
                        location: start_location,
                    }))
                }
            }
            '&' => {
                if self.match_char('&') {
                    Ok(Some(Token {
                        token_type: TokenType::And,
                        value: "&&".to_string(),
                        location: start_location,
                    }))
                } else {
                    Err(LexerError {
                        message: "Unexpected character '&'".to_string(),
                        location: start_location,
                    })
                }
            }
            '|' => {
                if self.match_char('|') {
                    Ok(Some(Token {
                        token_type: TokenType::Or,
                        value: "||".to_string(),
                        location: start_location,
                    }))
                } else {
                    Err(LexerError {
                        message: "Unexpected character '|'".to_string(),
                        location: start_location,
                    })
                }
            }
            '(' => Ok(Some(Token {
                token_type: TokenType::LeftParen,
                value: "(".to_string(),
                location: start_location,
            })),
            ')' => Ok(Some(Token {
                token_type: TokenType::RightParen,
                value: ")".to_string(),
                location: start_location,
            })),
            '{' => Ok(Some(Token {
                token_type: TokenType::LeftBrace,
                value: "{".to_string(),
                location: start_location,
            })),
            '}' => Ok(Some(Token {
                token_type: TokenType::RightBrace,
                value: "}".to_string(),
                location: start_location,
            })),
            '[' => Ok(Some(Token {
                token_type: TokenType::LeftBracket,
                value: "[".to_string(),
                location: start_location,
            })),
            ']' => Ok(Some(Token {
                token_type: TokenType::RightBracket,
                value: "]".to_string(),
                location: start_location,
            })),
            ',' => Ok(Some(Token {
                token_type: TokenType::Comma,
                value: ",".to_string(),
                location: start_location,
            })),
            ';' => Ok(Some(Token {
                token_type: TokenType::Semicolon,
                value: ";".to_string(),
                location: start_location,
            })),
            ':' => {
                if self.match_char(':') {
                    Ok(Some(Token {
                        token_type: TokenType::DoubleColon,
                        value: "::".to_string(),
                        location: start_location,
                    }))
                } else {
                    Ok(Some(Token {
                        token_type: TokenType::Colon,
                        value: ":".to_string(),
                        location: start_location,
                    }))
                }
            }
            '.' => Ok(Some(Token {
                token_type: TokenType::Dot,
                value: ".".to_string(),
                location: start_location,
            })),
            '?' => Ok(Some(Token {
                token_type: TokenType::Question,
                value: "?".to_string(),
                location: start_location,
            })),
            '@' => {
                // Check for privacy annotations like @private, @public, @secure
                if self.peek().is_alphabetic() {
                    let annotation = self.scan_annotation();
                    match annotation.as_str() {
                        "private" | "public" | "confidential" | "secret" | "anonymous" => {
                            Ok(Some(Token {
                                token_type: TokenType::PrivacyLevel_(annotation.clone()),
                                value: format!("@{}", annotation),
                                location: start_location,
                            }))
                        }
                        "secure" | "trusted" | "verified" => {
                            Ok(Some(Token {
                                token_type: TokenType::SecurityLevel_(annotation.clone()),
                                value: format!("@{}", annotation),
                                location: start_location,
                            }))
                        }
                        _ => {
                            Ok(Some(Token {
                                token_type: TokenType::At,
                                value: "@".to_string(),
                                location: start_location,
                            }))
                        }
                    }
                } else {
                    Ok(Some(Token {
                        token_type: TokenType::At,
                        value: "@".to_string(),
                        location: start_location,
                    }))
                }
            }
            '"' => {
                let string_literal = self.scan_string()?;
                Ok(Some(Token {
                    token_type: TokenType::String,
                    value: string_literal,
                    location: start_location,
                }))
            }
            '\'' => {
                let string_literal = self.scan_char_string()?;
                Ok(Some(Token {
                    token_type: TokenType::String,
                    value: string_literal,
                    location: start_location,
                }))
            }
            ch if ch.is_ascii_digit() => {
                let number = self.scan_number(ch)?;
                let token_type = if number.contains('.') {
                    TokenType::Float
                } else {
                    TokenType::Integer
                };
                Ok(Some(Token {
                    token_type,
                    value: number,
                    location: start_location,
                }))
            }
            ch if ch.is_alphabetic() || ch == '_' => {
                let identifier = self.scan_identifier(ch);
                let token_type = self.keywords.get(&identifier)
                    .cloned()
                    .unwrap_or(TokenType::Identifier);
                Ok(Some(Token {
                    token_type,
                    value: identifier,
                    location: start_location,
                }))
            }
            _ => Err(LexerError {
                message: format!("Unexpected character: '{}'", ch),
                location: start_location,
            }),
        }
    }

    /// Check if at end of source
    fn is_at_end(&self) -> bool {
        self.position >= self.source.len()
    }

    /// Advance to next character
    fn advance(&mut self) -> char {
        if self.is_at_end() {
            '\0'
        } else {
            let ch = self.source.chars().nth(self.position).unwrap_or('\0');
            self.position += 1;
            self.column += 1;
            ch
        }
    }

    /// Peek at current character without advancing
    fn peek(&self) -> char {
        if self.is_at_end() {
            '\0'
        } else {
            self.source.chars().nth(self.position).unwrap_or('\0')
        }
    }

    /// Peek at next character
    fn peek_next(&self) -> char {
        if self.position + 1 >= self.source.len() {
            '\0'
        } else {
            self.source.chars().nth(self.position + 1).unwrap_or('\0')
        }
    }

    /// Match specific character and advance if found
    fn match_char(&mut self, expected: char) -> bool {
        if self.peek() == expected {
            self.advance();
            true
        } else {
            false
        }
    }

    /// Get current source location
    fn current_location(&self) -> SourceLocation {
        SourceLocation::new("".to_string(), self.line, self.column, self.position)
    }

    /// Skip whitespace characters
    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), ' ' | '\r' | '\t') {
            self.advance();
        }
    }

    /// Scan line comment
    fn scan_line_comment(&mut self) -> String {
        let mut comment = String::from("//");
        while self.peek() != '\n' && !self.is_at_end() {
            comment.push(self.advance());
        }
        comment
    }

    /// Scan block comment
    fn scan_block_comment(&mut self) -> Result<String, LexerError> {
        let mut comment = String::from("/*");
        let start_location = self.current_location();

        while !self.is_at_end() {
            if self.peek() == '*' && self.peek_next() == '/' {
                comment.push(self.advance()); // *
                comment.push(self.advance()); // /
                return Ok(comment);
            }
            if self.peek() == '\n' {
                self.line += 1;
                self.column = 1;
            }
            comment.push(self.advance());
        }

        Err(LexerError {
            message: "Unterminated block comment".to_string(),
            location: start_location,
        })
    }

    /// Scan string literal
    fn scan_string(&mut self) -> Result<String, LexerError> {
        let mut string = String::new();
        let start_location = self.current_location();

        while self.peek() != '"' && !self.is_at_end() {
            if self.peek() == '\n' {
                self.line += 1;
                self.column = 1;
            }
            if self.peek() == '\\' {
                self.advance(); // consume backslash
                match self.peek() {
                    'n' => {
                        string.push('\n');
                        self.advance();
                    }
                    't' => {
                        string.push('\t');
                        self.advance();
                    }
                    'r' => {
                        string.push('\r');
                        self.advance();
                    }
                    '\\' => {
                        string.push('\\');
                        self.advance();
                    }
                    '"' => {
                        string.push('"');
                        self.advance();
                    }
                    _ => {
                        string.push(self.advance());
                    }
                }
            } else {
                string.push(self.advance());
            }
        }

        if self.is_at_end() {
            return Err(LexerError {
                message: "Unterminated string".to_string(),
                location: start_location,
            });
        }

        // Consume closing quote
        self.advance();
        Ok(string)
    }

    /// Scan character string (single quotes)
    fn scan_char_string(&mut self) -> Result<String, LexerError> {
        let mut string = String::new();
        let start_location = self.current_location();

        while self.peek() != '\'' && !self.is_at_end() {
            if self.peek() == '\\' {
                self.advance(); // consume backslash
                match self.peek() {
                    'n' => {
                        string.push('\n');
                        self.advance();
                    }
                    't' => {
                        string.push('\t');
                        self.advance();
                    }
                    'r' => {
                        string.push('\r');
                        self.advance();
                    }
                    '\\' => {
                        string.push('\\');
                        self.advance();
                    }
                    '\'' => {
                        string.push('\'');
                        self.advance();
                    }
                    _ => {
                        string.push(self.advance());
                    }
                }
            } else {
                string.push(self.advance());
            }
        }

        if self.is_at_end() {
            return Err(LexerError {
                message: "Unterminated character string".to_string(),
                location: start_location,
            });
        }

        // Consume closing quote
        self.advance();
        Ok(string)
    }

    /// Scan number literal
    fn scan_number(&mut self, first_digit: char) -> Result<String, LexerError> {
        let mut number = String::new();
        number.push(first_digit);

        // Scan integer part
        while self.peek().is_ascii_digit() {
            number.push(self.advance());
        }

        // Check for decimal point
        if self.peek() == '.' && self.peek_next().is_ascii_digit() {
            number.push(self.advance()); // consume .
            while self.peek().is_ascii_digit() {
                number.push(self.advance());
            }
        }

        // Check for exponent
        if matches!(self.peek(), 'e' | 'E') {
            number.push(self.advance());
            if matches!(self.peek(), '+' | '-') {
                number.push(self.advance());
            }
            if !self.peek().is_ascii_digit() {
                return Err(LexerError {
                    message: "Invalid number format".to_string(),
                    location: self.current_location(),
                });
            }
            while self.peek().is_ascii_digit() {
                number.push(self.advance());
            }
        }

        Ok(number)
    }

    /// Scan identifier
    fn scan_identifier(&mut self, first_char: char) -> String {
        let mut identifier = String::new();
        identifier.push(first_char);

        while self.peek().is_alphanumeric() || self.peek() == '_' {
            identifier.push(self.advance());
        }

        identifier
    }

    /// Scan annotation after @ symbol
    fn scan_annotation(&mut self) -> String {
        let mut annotation = String::new();

        while self.peek().is_alphanumeric() || self.peek() == '_' {
            annotation.push(self.advance());
        }

        annotation
    }
}

impl From<LexerError> for NymScriptError {
    fn from(error: LexerError) -> Self {
        NymScriptError::with_location(
            error.message,
            ErrorType::Lexical,
            ErrorSeverity::Error,
            error.location,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_tokens() {
        let mut lexer = NymScriptLexer::new("( ) { } [ ]");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens.len(), 7); // 6 tokens + EOF
        assert_eq!(tokens[0].token_type, TokenType::LeftParen);
        assert_eq!(tokens[1].token_type, TokenType::RightParen);
        assert_eq!(tokens[2].token_type, TokenType::LeftBrace);
        assert_eq!(tokens[3].token_type, TokenType::RightBrace);
        assert_eq!(tokens[4].token_type, TokenType::LeftBracket);
        assert_eq!(tokens[5].token_type, TokenType::RightBracket);
        assert_eq!(tokens[6].token_type, TokenType::EOF);
    }

    #[test]
    fn test_operators() {
        let mut lexer = NymScriptLexer::new("+ - * / == != <= >= && ||");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0].token_type, TokenType::Plus);
        assert_eq!(tokens[1].token_type, TokenType::Minus);
        assert_eq!(tokens[2].token_type, TokenType::Star);
        assert_eq!(tokens[3].token_type, TokenType::Slash);
        assert_eq!(tokens[4].token_type, TokenType::Equal);
        assert_eq!(tokens[5].token_type, TokenType::NotEqual);
        assert_eq!(tokens[6].token_type, TokenType::LessEqual);
        assert_eq!(tokens[7].token_type, TokenType::GreaterEqual);
        assert_eq!(tokens[8].token_type, TokenType::And);
        assert_eq!(tokens[9].token_type, TokenType::Or);
    }

    #[test]
    fn test_privacy_operators() {
        let mut lexer = NymScriptLexer::new("++= **= ===");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0].token_type, TokenType::PrivateAdd);
        assert_eq!(tokens[0].value, "++=");
        assert_eq!(tokens[1].token_type, TokenType::PrivateMul);
        assert_eq!(tokens[1].value, "**=");
        assert_eq!(tokens[2].token_type, TokenType::PrivateEq);
        assert_eq!(tokens[2].value, "===");
    }

    #[test]
    fn test_keywords() {
        let mut lexer = NymScriptLexer::new("contract fn let mut private public");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0].token_type, TokenType::Contract);
        assert_eq!(tokens[1].token_type, TokenType::Function);
        assert_eq!(tokens[2].token_type, TokenType::Let);
        assert_eq!(tokens[3].token_type, TokenType::Mut);
        assert_eq!(tokens[4].token_type, TokenType::Private);
        assert_eq!(tokens[5].token_type, TokenType::Public);
    }

    #[test]
    fn test_privacy_keywords() {
        let mut lexer = NymScriptLexer::new("private public confidential secret anonymous");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0].token_type, TokenType::Private);
        assert_eq!(tokens[1].token_type, TokenType::Public);
        assert_eq!(tokens[2].token_type, TokenType::Confidential);
        assert_eq!(tokens[3].token_type, TokenType::Secret);
        assert_eq!(tokens[4].token_type, TokenType::Anonymous);
    }

    #[test]
    fn test_crypto_keywords() {
        let mut lexer = NymScriptLexer::new("encrypt decrypt proof verify commit reveal");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0].token_type, TokenType::Encrypt);
        assert_eq!(tokens[1].token_type, TokenType::Decrypt);
        assert_eq!(tokens[2].token_type, TokenType::Proof);
        assert_eq!(tokens[3].token_type, TokenType::Verify);
        assert_eq!(tokens[4].token_type, TokenType::Commit);
        assert_eq!(tokens[5].token_type, TokenType::Reveal);
    }

    #[test]
    fn test_identifiers() {
        let mut lexer = NymScriptLexer::new("variable_name camelCase snake_case");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0].token_type, TokenType::Identifier);
        assert_eq!(tokens[0].value, "variable_name");
        assert_eq!(tokens[1].token_type, TokenType::Identifier);
        assert_eq!(tokens[1].value, "camelCase");
        assert_eq!(tokens[2].token_type, TokenType::Identifier);
        assert_eq!(tokens[2].value, "snake_case");
    }

    #[test]
    fn test_numbers() {
        let mut lexer = NymScriptLexer::new("42 3.14 1e10 2.5e-3");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0].token_type, TokenType::Integer);
        assert_eq!(tokens[0].value, "42");
        assert_eq!(tokens[1].token_type, TokenType::Float);
        assert_eq!(tokens[1].value, "3.14");
        assert_eq!(tokens[2].token_type, TokenType::Float);
        assert_eq!(tokens[2].value, "1e10");
        assert_eq!(tokens[3].token_type, TokenType::Float);
        assert_eq!(tokens[3].value, "2.5e-3");
    }

    #[test]
    fn test_strings() {
        let mut lexer = NymScriptLexer::new(r#""hello world" 'single quotes' "escaped \"quote\"" "#);
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0].token_type, TokenType::String);
        assert_eq!(tokens[0].value, "hello world");
        assert_eq!(tokens[1].token_type, TokenType::String);
        assert_eq!(tokens[1].value, "single quotes");
        assert_eq!(tokens[2].token_type, TokenType::String);
        assert_eq!(tokens[2].value, "escaped \"quote\"");
    }

    #[test]
    fn test_comments() {
        let mut lexer = NymScriptLexer::new("// line comment\n/* block comment */");
        let tokens = lexer.tokenize().unwrap();

        // Should only have newline and EOF (comments are filtered)
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].token_type, TokenType::Newline);
        assert_eq!(tokens[1].token_type, TokenType::EOF);
    }

    #[test]
    fn test_location_tracking() {
        let mut lexer = NymScriptLexer::new("fn\ntest");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0].location.line, 1);
        assert_eq!(tokens[0].location.column, 1);
        assert_eq!(tokens[1].location.line, 1); // newline
        assert_eq!(tokens[2].location.line, 2);
        assert_eq!(tokens[2].location.column, 1);
    }

    #[test]
    fn test_error_handling() {
        let mut lexer = NymScriptLexer::new("\"unterminated string");
        let result = lexer.tokenize();

        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("Unterminated string"));
    }

    #[test]
    fn test_privacy_levels() {
        let mut lexer = NymScriptLexer::new("@private @public @confidential");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0].token_type, TokenType::At);
        assert_eq!(tokens[1].token_type, TokenType::Private);
        assert_eq!(tokens[2].token_type, TokenType::At);
        assert_eq!(tokens[3].token_type, TokenType::Public);
        assert_eq!(tokens[4].token_type, TokenType::At);
        assert_eq!(tokens[5].token_type, TokenType::Confidential);
    }

    #[test]
    fn test_arrows() {
        let mut lexer = NymScriptLexer::new("-> =>");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0].token_type, TokenType::Arrow);
        assert_eq!(tokens[0].value, "->");
        assert_eq!(tokens[1].token_type, TokenType::FatArrow);
        assert_eq!(tokens[1].value, "=>");
    }

    #[test]
    fn test_assignment_operators() {
        let mut lexer = NymScriptLexer::new("+= -= *= /=");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0].token_type, TokenType::PlusAssign);
        assert_eq!(tokens[1].token_type, TokenType::MinusAssign);
        assert_eq!(tokens[2].token_type, TokenType::StarAssign);
        assert_eq!(tokens[3].token_type, TokenType::SlashAssign);
    }

    #[test]
    fn test_privacy_annotations() {
        let mut lexer = NymScriptLexer::new("@private @public @secure @trusted");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0].token_type, TokenType::PrivacyLevel_("private".to_string()));
        assert_eq!(tokens[0].value, "@private");
        assert_eq!(tokens[1].token_type, TokenType::PrivacyLevel_("public".to_string()));
        assert_eq!(tokens[1].value, "@public");
        assert_eq!(tokens[2].token_type, TokenType::SecurityLevel_("secure".to_string()));
        assert_eq!(tokens[2].value, "@secure");
        assert_eq!(tokens[3].token_type, TokenType::SecurityLevel_("trusted".to_string()));
        assert_eq!(tokens[3].value, "@trusted");
    }

    #[test]
    fn test_zk_keywords() {
        let mut lexer = NymScriptLexer::new("circuit witness");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0].token_type, TokenType::ZKCircuit);
        assert_eq!(tokens[0].value, "circuit");
        assert_eq!(tokens[1].token_type, TokenType::ZKWitness);
        assert_eq!(tokens[1].value, "witness");
    }

    #[test]
    fn test_macro_keywords() {
        let mut lexer = NymScriptLexer::new("macro include module use import export");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0].token_type, TokenType::Macro);
        assert_eq!(tokens[1].token_type, TokenType::Include);
        assert_eq!(tokens[2].token_type, TokenType::Module);
        assert_eq!(tokens[3].token_type, TokenType::Use);
        assert_eq!(tokens[4].token_type, TokenType::Import);
        assert_eq!(tokens[5].token_type, TokenType::Export);
    }

    #[test]
    fn test_complex_privacy_example() {
        let mut lexer = NymScriptLexer::new("@private fn test() -> @confidential int { ++= **= === }");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0].token_type, TokenType::PrivacyLevel_("private".to_string()));
        assert_eq!(tokens[1].token_type, TokenType::Function);
        assert_eq!(tokens[2].token_type, TokenType::Identifier);
        assert_eq!(tokens[2].value, "test");
        assert_eq!(tokens[3].token_type, TokenType::LeftParen);
        assert_eq!(tokens[4].token_type, TokenType::RightParen);
        assert_eq!(tokens[5].token_type, TokenType::Arrow);
        assert_eq!(tokens[6].token_type, TokenType::PrivacyLevel_("confidential".to_string()));
        assert_eq!(tokens[7].token_type, TokenType::Int);
        assert_eq!(tokens[8].token_type, TokenType::LeftBrace);
        assert_eq!(tokens[9].token_type, TokenType::PrivateAdd);
        assert_eq!(tokens[10].token_type, TokenType::PrivateMul);
        assert_eq!(tokens[11].token_type, TokenType::PrivateEq);
        assert_eq!(tokens[12].token_type, TokenType::RightBrace);
    }
}