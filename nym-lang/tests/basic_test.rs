//! Basic tests for NymScript compiler
//! This file tests core functionality without complex dependencies

#[cfg(test)]
mod tests {
    use nym_lang::lexer::{NymScriptLexer, TokenType};
    use nym_lang::parser::NymScriptParser;
    use nym_lang::ast::PrivacyLevel;

    #[test]
    fn test_basic_lexing() {
        let source = "let x = 42;";
        let mut lexer = NymScriptLexer::new(source);
        let tokens = lexer.tokenize().unwrap();
        
        assert!(!tokens.is_empty());
        assert_eq!(tokens[0].token_type, TokenType::Let);
    }

    #[test]
    fn test_privacy_level_creation() {
        let private_level = PrivacyLevel::Private;
        let public_level = PrivacyLevel::Public;
        
        assert_ne!(private_level, public_level);
    }

    #[test]
    fn test_parser_creation() {
        let source = "let x = 42;";
        let mut lexer = NymScriptLexer::new(source);
        let tokens = lexer.tokenize().unwrap();
        let mut parser = NymScriptParser::new(tokens);
        
        // Just test that parser can be created
        let _result = parser.parse();
    }
}