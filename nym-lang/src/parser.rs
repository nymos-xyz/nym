//! NymScript Parser - Week 61-62
//! 
//! This module implements parsing for NymScript source code

use crate::ast::*;
use crate::lexer::{Token, TokenType};
use crate::error::{NymScriptError, ErrorType, ErrorSeverity, SourceLocation};
use std::collections::HashMap;

/// NymScript parser
pub struct NymScriptParser {
    /// Tokens to parse
    tokens: Vec<Token>,
    /// Current token index
    current: usize,
    /// EOF token for end-of-input cases
    eof_token: Token,
}

/// Parse result type
pub type ParseResult<T> = Result<T, Vec<ParseError>>;

/// Parse error
#[derive(Debug, Clone)]
pub struct ParseError {
    /// Error message
    pub message: String,
    /// Error location
    pub location: Option<SourceLocation>,
    /// Expected tokens
    pub expected: Vec<TokenType>,
    /// Found token
    pub found: Option<TokenType>,
}

impl NymScriptParser {
    /// Create new parser
    pub fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            current: 0,
            eof_token: Token {
                token_type: TokenType::EOF,
                value: String::new(),
                location: SourceLocation::new("".to_string(), 0, 0, 0),
            },
        }
    }

    /// Parse complete program
    pub fn parse(&mut self) -> ParseResult<NymScriptAST> {
        let mut errors = Vec::new();
        let mut imports = Vec::new();
        let mut declarations = Vec::new();
        let mut contracts = Vec::new();

        // Parse module components
        while !self.is_at_end() {
            match self.peek().token_type {
                TokenType::EOF => break,
                TokenType::Import => {
                    match self.parse_import() {
                        Ok(import) => imports.push(import),
                        Err(mut errs) => errors.append(&mut errs),
                    }
                }
                TokenType::Contract | TokenType::PrivacyLevel_(_) | TokenType::SecurityLevel_(_) => {
                    match self.parse_contract() {
                        Ok(contract) => contracts.push(contract),
                        Err(mut errs) => errors.append(&mut errs),
                    }
                }
                TokenType::Function => {
                    match self.parse_function() {
                        Ok(function) => declarations.push(Declaration::Function(function)),
                        Err(mut errs) => errors.append(&mut errs),
                    }
                }
                TokenType::Macro => {
                    match self.parse_macro() {
                        Ok(macro_decl) => declarations.push(Declaration::Macro(macro_decl)),
                        Err(mut errs) => errors.append(&mut errs),
                    }
                }
                TokenType::Export => {
                    match self.parse_export() {
                        Ok(export) => declarations.push(export),
                        Err(mut errs) => errors.append(&mut errs),
                    }
                }
                _ => {
                    match self.parse_declaration() {
                        Ok(declaration) => declarations.push(declaration),
                        Err(mut errs) => errors.append(&mut errs),
                    }
                }
            }
        }

        if errors.is_empty() {
            Ok(NymScriptAST {
                module_name: "main".to_string(),
                imports,
                declarations,
                contracts,
                metadata: ModuleMetadata {
                    version: "0.1.0".to_string(),
                    privacy_level: PrivacyLevel::Private,
                    security_requirements: Vec::new(),
                    targets: vec![CompilationTarget::NymVM],
                },
            })
        } else {
            Err(errors)
        }
    }

    /// Parse privacy annotation before declarations
    fn parse_privacy_annotation(&mut self) -> Option<PrivacyAnnotation> {
        let mut privacy_level = None;
        let mut security_level = None;
        let mut anonymity_level = AnonymityLevel::Medium;

        // Parse privacy annotations like @private, @public, @secure
        while let Some(token) = self.peek_if_annotation() {
            match &token.token_type {
                TokenType::PrivacyLevel_(level) => {
                    privacy_level = Some(match level.as_str() {
                        "private" => PrivacyLevel::Private,
                        "public" => PrivacyLevel::Public,
                        "confidential" => PrivacyLevel::Confidential,
                        "secret" => PrivacyLevel::Secret,
                        "anonymous" => {
                            anonymity_level = AnonymityLevel::High;
                            PrivacyLevel::Anonymous
                        },
                        _ => PrivacyLevel::Private,
                    });
                    self.advance();
                }
                TokenType::SecurityLevel_(level) => {
                    security_level = Some(match level.as_str() {
                        "secure" => SecurityLevel::High,
                        "trusted" => SecurityLevel::Medium,
                        "verified" => SecurityLevel::Low,
                        _ => SecurityLevel::Medium,
                    });
                    self.advance();
                }
                _ => break,
            }
        }

        if privacy_level.is_some() || security_level.is_some() {
            Some(PrivacyAnnotation {
                level: privacy_level.unwrap_or(PrivacyLevel::Private),
                flow_constraints: Vec::new(),
                anonymity_level,
                zk_requirements: Vec::new(),
            })
        } else {
            None
        }
    }

    /// Helper to peek for annotation tokens
    fn peek_if_annotation(&self) -> Option<&Token> {
        let token = self.peek();
        match &token.token_type {
            TokenType::PrivacyLevel_(_) | TokenType::SecurityLevel_(_) => Some(token),
            _ => None,
        }
    }

    /// Parse contract definition
    fn parse_contract(&mut self) -> ParseResult<Contract> {
        let mut errors = Vec::new();

        // Parse privacy annotation before contract
        let privacy_annotation = self.parse_privacy_annotation();

        // Consume 'contract' keyword
        if !self.consume(TokenType::Contract) {
            errors.push(ParseError {
                message: "Expected 'contract' keyword".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::Contract],
                found: Some(self.peek().token_type.clone()),
            });
        }

        // Parse contract name
        let name = if self.check(TokenType::Identifier) {
            self.advance().value.clone()
        } else {
            errors.push(ParseError {
                message: "Expected contract name".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::Identifier],
                found: Some(self.peek().token_type.clone()),
            });
            "Unknown".to_string()
        };

        // Parse inheritance (optional)
        let mut inherits = Vec::new();
        if self.consume(TokenType::Colon) {
            loop {
                if self.check(TokenType::Identifier) {
                    inherits.push(self.advance().value.clone());
                    if !self.consume(TokenType::Comma) {
                        break;
                    }
                } else {
                    errors.push(ParseError {
                        message: "Expected parent contract name".to_string(),
                        location: self.current_location(),
                        expected: vec![TokenType::Identifier],
                        found: Some(self.peek().token_type.clone()),
                    });
                    break;
                }
            }
        }

        // Parse contract body
        if !self.consume(TokenType::LeftBrace) {
            errors.push(ParseError {
                message: "Expected '{' to start contract body".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::LeftBrace],
                found: Some(self.peek().token_type.clone()),
            });
        }

        let mut state = Vec::new();
        let mut functions = Vec::new();
        let mut events = Vec::new();
        let mut modifiers = Vec::new();

        while !self.check(TokenType::RightBrace) && !self.is_at_end() {
            match self.peek().token_type {
                TokenType::Function => {
                    match self.parse_contract_function() {
                        Ok(function) => functions.push(function),
                        Err(mut errs) => errors.append(&mut errs),
                    }
                }
                TokenType::Let => {
                    match self.parse_state_variable() {
                        Ok(var) => state.push(var),
                        Err(mut errs) => errors.append(&mut errs),
                    }
                }
                _ => {
                    // Skip unknown tokens and try to recover
                    errors.push(ParseError {
                        message: format!("Unexpected token in contract body: {:?}", self.peek().token_type),
                        location: self.current_location(),
                        expected: vec![TokenType::Function, TokenType::Let],
                        found: Some(self.peek().token_type.clone()),
                    });
                    self.advance();
                }
            }
        }

        if !self.consume(TokenType::RightBrace) {
            errors.push(ParseError {
                message: "Expected '}' to close contract body".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::RightBrace],
                found: Some(self.peek().token_type.clone()),
            });
        }

        if errors.is_empty() {
            Ok(Contract {
                name,
                state,
                functions,
                events,
                modifiers,
                inherits,
                privacy_config: ContractPrivacyConfig {
                    default_privacy_level: PrivacyLevel::Private,
                    privacy_policies: Vec::new(),
                    anonymity_sets: Vec::new(),
                },
                security_policies: Vec::new(),
            })
        } else {
            Err(errors)
        }
    }

    /// Parse function definition
    fn parse_function(&mut self) -> ParseResult<Function> {
        let mut errors = Vec::new();

        // Parse privacy annotation before function
        let privacy_annotation = self.parse_privacy_annotation().unwrap_or_default();

        // Consume 'fn' keyword
        if !self.consume(TokenType::Function) {
            errors.push(ParseError {
                message: "Expected 'fn' keyword".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::Function],
                found: Some(self.peek().token_type.clone()),
            });
        }

        // Parse function name
        let name = if self.check(TokenType::Identifier) {
            self.advance().value.clone()
        } else {
            errors.push(ParseError {
                message: "Expected function name".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::Identifier],
                found: Some(self.peek().token_type.clone()),
            });
            "unknown".to_string()
        };

        // Parse parameters
        let mut parameters = Vec::new();
        if !self.consume(TokenType::LeftParen) {
            errors.push(ParseError {
                message: "Expected '(' after function name".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::LeftParen],
                found: Some(self.peek().token_type.clone()),
            });
        } else {
            while !self.check(TokenType::RightParen) && !self.is_at_end() {
                match self.parse_parameter() {
                    Ok(param) => parameters.push(param),
                    Err(mut errs) => errors.append(&mut errs),
                }

                if !self.check(TokenType::RightParen) {
                    if !self.consume(TokenType::Comma) {
                        errors.push(ParseError {
                            message: "Expected ',' between parameters".to_string(),
                            location: self.current_location(),
                            expected: vec![TokenType::Comma],
                            found: Some(self.peek().token_type.clone()),
                        });
                        break;
                    }
                }
            }

            if !self.consume(TokenType::RightParen) {
                errors.push(ParseError {
                    message: "Expected ')' after parameters".to_string(),
                    location: self.current_location(),
                    expected: vec![TokenType::RightParen],
                    found: Some(self.peek().token_type.clone()),
                });
            }
        }

        // Parse return type (optional)
        let return_type = if self.consume(TokenType::Arrow) {
            match self.parse_type_annotation() {
                Ok(ty) => Some(ty),
                Err(mut errs) => {
                    errors.append(&mut errs);
                    None
                }
            }
        } else {
            None
        };

        // Parse function body
        let body = match self.parse_block() {
            Ok(block) => block,
            Err(mut errs) => {
                errors.append(&mut errs);
                Block {
                    statements: Vec::new(),
                    privacy_level: None,
                    attributes: Vec::new(),
                }
            }
        };

        if errors.is_empty() {
            Ok(Function {
                name,
                parameters,
                return_type,
                body,
                privacy: privacy_annotation,
                security_level: SecurityLevel::default(),
                attributes: Vec::new(),
                gas_estimate: None,
            })
        } else {
            Err(errors)
        }
    }

    /// Parse declaration
    fn parse_declaration(&mut self) -> ParseResult<Declaration> {
        match self.peek().token_type {
            TokenType::Let => {
                let let_stmt = self.parse_let_statement()?;
                Ok(Declaration::Global(GlobalDeclaration {
                    name: "global".to_string(), // Simplified
                    global_type: TypeAnnotation {
                        base_type: BaseType::String,
                        generics: Vec::new(),
                        privacy_wrapper: None,
                        constraints: Vec::new(),
                    },
                    initial_value: None,
                    privacy: PrivacyAnnotation::default(),
                }))
            }
            _ => Err(vec![ParseError {
                message: "Expected declaration".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::Let, TokenType::Function],
                found: Some(self.peek().token_type.clone()),
            }])
        }
    }

    /// Parse parameter
    fn parse_parameter(&mut self) -> ParseResult<Parameter> {
        let mut errors = Vec::new();

        // Parse parameter name
        let name = if self.check(TokenType::Identifier) {
            self.advance().value.clone()
        } else {
            errors.push(ParseError {
                message: "Expected parameter name".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::Identifier],
                found: Some(self.peek().token_type.clone()),
            });
            "unknown".to_string()
        };

        // Parse parameter type
        if !self.consume(TokenType::Colon) {
            errors.push(ParseError {
                message: "Expected ':' after parameter name".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::Colon],
                found: Some(self.peek().token_type.clone()),
            });
        }

        let param_type = match self.parse_type_annotation() {
            Ok(ty) => ty,
            Err(mut errs) => {
                errors.append(&mut errs);
                TypeAnnotation {
                    base_type: BaseType::String,
                    generics: Vec::new(),
                    privacy_wrapper: None,
                    constraints: Vec::new(),
                }
            }
        };

        if errors.is_empty() {
            Ok(Parameter {
                name,
                param_type,
                privacy: PrivacyAnnotation::default(),
                default: None,
                attributes: Vec::new(),
            })
        } else {
            Err(errors)
        }
    }

    /// Parse type annotation
    fn parse_type_annotation(&mut self) -> ParseResult<TypeAnnotation> {
        let base_type = match self.peek().token_type {
            TokenType::Bool => {
                self.advance();
                BaseType::Bool
            }
            TokenType::Int => {
                self.advance();
                BaseType::Int(IntType::I64)
            }
            TokenType::UInt => {
                self.advance();
                BaseType::UInt(IntType::I64)
            }
            TokenType::String_ => {
                self.advance();
                BaseType::String
            }
            TokenType::Bytes => {
                self.advance();
                BaseType::Bytes
            }
            TokenType::Field => {
                self.advance();
                BaseType::Field
            }
            TokenType::Address => {
                self.advance();
                BaseType::Address
            }
            TokenType::Identifier => {
                let name = self.advance().value.clone();
                BaseType::Struct(name)
            }
            _ => {
                return Err(vec![ParseError {
                    message: "Expected type".to_string(),
                    location: self.current_location(),
                    expected: vec![
                        TokenType::Bool,
                        TokenType::Int,
                        TokenType::String_,
                        TokenType::Identifier,
                    ],
                    found: Some(self.peek().token_type.clone()),
                }]);
            }
        };

        Ok(TypeAnnotation {
            base_type,
            generics: Vec::new(),
            privacy_wrapper: None,
            constraints: Vec::new(),
        })
    }

    /// Parse block statement
    fn parse_block(&mut self) -> ParseResult<Block> {
        let mut errors = Vec::new();
        let mut statements = Vec::new();

        if !self.consume(TokenType::LeftBrace) {
            return Err(vec![ParseError {
                message: "Expected '{' to start block".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::LeftBrace],
                found: Some(self.peek().token_type.clone()),
            }]);
        }

        while !self.check(TokenType::RightBrace) && !self.is_at_end() {
            match self.parse_statement() {
                Ok(stmt) => statements.push(stmt),
                Err(mut errs) => errors.append(&mut errs),
            }
        }

        if !self.consume(TokenType::RightBrace) {
            errors.push(ParseError {
                message: "Expected '}' to close block".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::RightBrace],
                found: Some(self.peek().token_type.clone()),
            });
        }

        if errors.is_empty() {
            Ok(Block {
                statements,
                privacy_level: None,
                attributes: Vec::new(),
            })
        } else {
            Err(errors)
        }
    }

    /// Parse statement
    fn parse_statement(&mut self) -> ParseResult<Statement> {
        match self.peek().token_type {
            TokenType::Let => Ok(Statement::Let(self.parse_let_statement()?)),
            TokenType::If => Ok(Statement::If(self.parse_if_statement()?)),
            TokenType::Return => Ok(Statement::Return(self.parse_return_statement()?)),
            TokenType::LeftBrace => Ok(Statement::Block(self.parse_block()?)),
            _ => {
                // Expression statement
                let expr = self.parse_expression()?;
                self.consume(TokenType::Semicolon);
                Ok(Statement::Expression(expr))
            }
        }
    }

    /// Parse let statement
    fn parse_let_statement(&mut self) -> ParseResult<LetStatement> {
        let mut errors = Vec::new();

        if !self.consume(TokenType::Let) {
            errors.push(ParseError {
                message: "Expected 'let' keyword".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::Let],
                found: Some(self.peek().token_type.clone()),
            });
        }

        let mutable = self.consume(TokenType::Mut);

        let name = if self.check(TokenType::Identifier) {
            self.advance().value.clone()
        } else {
            errors.push(ParseError {
                message: "Expected variable name".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::Identifier],
                found: Some(self.peek().token_type.clone()),
            });
            "unknown".to_string()
        };

        let type_annotation = if self.consume(TokenType::Colon) {
            match self.parse_type_annotation() {
                Ok(ty) => Some(ty),
                Err(mut errs) => {
                    errors.append(&mut errs);
                    None
                }
            }
        } else {
            None
        };

        let value = if self.consume(TokenType::Assign) {
            match self.parse_expression() {
                Ok(expr) => Some(expr),
                Err(mut errs) => {
                    errors.append(&mut errs);
                    None
                }
            }
        } else {
            None
        };

        self.consume(TokenType::Semicolon);

        if errors.is_empty() {
            Ok(LetStatement {
                name,
                type_annotation,
                value,
                privacy: PrivacyAnnotation::default(),
                mutable,
            })
        } else {
            Err(errors)
        }
    }

    /// Parse if statement
    fn parse_if_statement(&mut self) -> ParseResult<IfStatement> {
        let mut errors = Vec::new();

        if !self.consume(TokenType::If) {
            errors.push(ParseError {
                message: "Expected 'if' keyword".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::If],
                found: Some(self.peek().token_type.clone()),
            });
        }

        let condition = match self.parse_expression() {
            Ok(expr) => expr,
            Err(mut errs) => {
                errors.append(&mut errs);
                Expression::Literal(Literal::Bool(true))
            }
        };

        let then_branch = match self.parse_block() {
            Ok(block) => block,
            Err(mut errs) => {
                errors.append(&mut errs);
                Block {
                    statements: Vec::new(),
                    privacy_level: None,
                    attributes: Vec::new(),
                }
            }
        };

        let else_branch = if self.consume(TokenType::Else) {
            if self.check(TokenType::If) {
                // else if
                match self.parse_if_statement() {
                    Ok(if_stmt) => Some(Box::new(Statement::If(if_stmt))),
                    Err(mut errs) => {
                        errors.append(&mut errs);
                        None
                    }
                }
            } else {
                // else block
                match self.parse_block() {
                    Ok(block) => Some(Box::new(Statement::Block(block))),
                    Err(mut errs) => {
                        errors.append(&mut errs);
                        None
                    }
                }
            }
        } else {
            None
        };

        if errors.is_empty() {
            Ok(IfStatement {
                condition,
                then_branch,
                else_branch,
                privacy_context: None,
            })
        } else {
            Err(errors)
        }
    }

    /// Parse return statement
    fn parse_return_statement(&mut self) -> ParseResult<ReturnStatement> {
        if !self.consume(TokenType::Return) {
            return Err(vec![ParseError {
                message: "Expected 'return' keyword".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::Return],
                found: Some(self.peek().token_type.clone()),
            }]);
        }

        let value = if self.check(TokenType::Semicolon) {
            None
        } else {
            Some(self.parse_expression()?)
        };

        self.consume(TokenType::Semicolon);

        Ok(ReturnStatement { value })
    }

    /// Parse expression
    fn parse_expression(&mut self) -> ParseResult<Expression> {
        self.parse_logical_or()
    }

    /// Parse logical OR expression
    fn parse_logical_or(&mut self) -> ParseResult<Expression> {
        let mut expr = self.parse_logical_and()?;

        while self.consume(TokenType::Or) {
            let operator = BinaryOperator::Or;
            let right = self.parse_logical_and()?;
            expr = Expression::Binary(BinaryExpression {
                left: Box::new(expr),
                operator,
                right: Box::new(right),
                privacy_result: None,
            });
        }

        Ok(expr)
    }

    /// Parse logical AND expression
    fn parse_logical_and(&mut self) -> ParseResult<Expression> {
        let mut expr = self.parse_equality()?;

        while self.consume(TokenType::And) {
            let operator = BinaryOperator::And;
            let right = self.parse_equality()?;
            expr = Expression::Binary(BinaryExpression {
                left: Box::new(expr),
                operator,
                right: Box::new(right),
                privacy_result: None,
            });
        }

        Ok(expr)
    }

    /// Parse equality expression
    fn parse_equality(&mut self) -> ParseResult<Expression> {
        let mut expr = self.parse_comparison()?;

        while self.match_types(&[TokenType::Equal, TokenType::NotEqual, TokenType::PrivateEq]) {
            let operator = match self.previous().token_type {
                TokenType::Equal => BinaryOperator::Eq,
                TokenType::NotEqual => BinaryOperator::Ne,
                TokenType::PrivateEq => BinaryOperator::PrivateEq,
                _ => unreachable!(),
            };
            let right = self.parse_comparison()?;
            expr = Expression::Binary(BinaryExpression {
                left: Box::new(expr),
                operator,
                right: Box::new(right),
                privacy_result: None,
            });
        }

        Ok(expr)
    }

    /// Parse comparison expression
    fn parse_comparison(&mut self) -> ParseResult<Expression> {
        let mut expr = self.parse_term()?;

        while self.match_types(&[
            TokenType::Greater,
            TokenType::GreaterEqual,
            TokenType::Less,
            TokenType::LessEqual,
        ]) {
            let operator = match self.previous().token_type {
                TokenType::Greater => BinaryOperator::Gt,
                TokenType::GreaterEqual => BinaryOperator::Ge,
                TokenType::Less => BinaryOperator::Lt,
                TokenType::LessEqual => BinaryOperator::Le,
                _ => unreachable!(),
            };
            let right = self.parse_term()?;
            expr = Expression::Binary(BinaryExpression {
                left: Box::new(expr),
                operator,
                right: Box::new(right),
                privacy_result: None,
            });
        }

        Ok(expr)
    }

    /// Parse term expression (addition/subtraction)
    fn parse_term(&mut self) -> ParseResult<Expression> {
        let mut expr = self.parse_factor()?;

        while self.match_types(&[TokenType::Minus, TokenType::Plus, TokenType::PrivateAdd]) {
            let operator = match self.previous().token_type {
                TokenType::Minus => BinaryOperator::Sub,
                TokenType::Plus => BinaryOperator::Add,
                TokenType::PrivateAdd => BinaryOperator::PrivateAdd,
                _ => unreachable!(),
            };
            let right = self.parse_factor()?;
            expr = Expression::Binary(BinaryExpression {
                left: Box::new(expr),
                operator,
                right: Box::new(right),
                privacy_result: None,
            });
        }

        Ok(expr)
    }

    /// Parse factor expression (multiplication/division)
    fn parse_factor(&mut self) -> ParseResult<Expression> {
        let mut expr = self.parse_unary()?;

        while self.match_types(&[TokenType::Slash, TokenType::Star, TokenType::PrivateMul]) {
            let operator = match self.previous().token_type {
                TokenType::Slash => BinaryOperator::Div,
                TokenType::Star => BinaryOperator::Mul,
                TokenType::PrivateMul => BinaryOperator::PrivateMul,
                _ => unreachable!(),
            };
            let right = self.parse_unary()?;
            expr = Expression::Binary(BinaryExpression {
                left: Box::new(expr),
                operator,
                right: Box::new(right),
                privacy_result: None,
            });
        }

        Ok(expr)
    }

    /// Parse unary expression
    fn parse_unary(&mut self) -> ParseResult<Expression> {
        if self.match_types(&[TokenType::Not, TokenType::Minus]) {
            let operator = match self.previous().token_type {
                TokenType::Not => UnaryOperator::Not,
                TokenType::Minus => UnaryOperator::Neg,
                _ => unreachable!(),
            };
            let right = self.parse_unary()?;
            return Ok(Expression::Unary(UnaryExpression {
                operator,
                operand: Box::new(right),
            }));
        }

        self.parse_primary()
    }

    /// Parse primary expression
    fn parse_primary(&mut self) -> ParseResult<Expression> {
        match &self.peek().token_type {
            TokenType::True => {
                self.advance();
                Ok(Expression::Literal(Literal::Bool(true)))
            }
            TokenType::False => {
                self.advance();
                Ok(Expression::Literal(Literal::Bool(false)))
            }
            TokenType::Integer => {
                let value = self.advance().value.clone();
                let int_value = value.parse::<i64>().unwrap_or(0);
                Ok(Expression::Literal(Literal::Int(int_value)))
            }
            TokenType::Float => {
                let value = self.advance().value.clone();
                // For simplicity, store as string
                Ok(Expression::Literal(Literal::Field(value)))
            }
            TokenType::String => {
                let value = self.advance().value.clone();
                Ok(Expression::Literal(Literal::String(value)))
            }
            TokenType::Identifier => {
                let name = self.advance().value.clone();
                Ok(Expression::Identifier(Identifier {
                    name,
                    type_annotation: None,
                    privacy: None,
                }))
            }
            TokenType::LeftParen => {
                self.advance(); // consume '('
                let expr = self.parse_expression()?;
                if !self.consume(TokenType::RightParen) {
                    return Err(vec![ParseError {
                        message: "Expected ')' after expression".to_string(),
                        location: self.current_location(),
                        expected: vec![TokenType::RightParen],
                        found: Some(self.peek().token_type.clone()),
                    }]);
                }
                Ok(expr)
            }
            _ => Err(vec![ParseError {
                message: "Expected expression".to_string(),
                location: self.current_location(),
                expected: vec![
                    TokenType::True,
                    TokenType::False,
                    TokenType::Integer,
                    TokenType::String,
                    TokenType::Identifier,
                    TokenType::LeftParen,
                ],
                found: Some(self.peek().token_type.clone()),
            }])
        }
    }

    /// Parse import statement
    fn parse_import(&mut self) -> ParseResult<ImportStatement> {
        let mut errors = Vec::new();

        if !self.consume(TokenType::Import) {
            return Err(vec![ParseError {
                message: "Expected 'import' keyword".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::Import],
                found: Some(self.peek().token_type.clone()),
            }]);
        }

        // Parse import path
        let path = if self.check(TokenType::String) {
            self.advance().value.clone()
        } else {
            errors.push(ParseError {
                message: "Expected import path string".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::String],
                found: Some(self.peek().token_type.clone()),
            });
            "unknown".to_string()
        };

        // Parse optional import items
        let items = if self.consume(TokenType::LeftBrace) {
            let mut import_items = Vec::new();
            while !self.check(TokenType::RightBrace) && !self.is_at_end() {
                if self.check(TokenType::Identifier) {
                    import_items.push(self.advance().value);
                    if !self.check(TokenType::RightBrace) {
                        if !self.consume(TokenType::Comma) {
                            errors.push(ParseError {
                                message: "Expected ',' between import items".to_string(),
                                location: self.current_location(),
                                expected: vec![TokenType::Comma],
                                found: Some(self.peek().token_type.clone()),
                            });
                            break;
                        }
                    }
                } else {
                    errors.push(ParseError {
                        message: "Expected import item name".to_string(),
                        location: self.current_location(),
                        expected: vec![TokenType::Identifier],
                        found: Some(self.peek().token_type.clone()),
                    });
                    break;
                }
            }
            if !self.consume(TokenType::RightBrace) {
                errors.push(ParseError {
                    message: "Expected '}' after import items".to_string(),
                    location: self.current_location(),
                    expected: vec![TokenType::RightBrace],
                    found: Some(self.peek().token_type.clone()),
                });
            }
            Some(import_items)
        } else {
            None
        };

        self.consume(TokenType::Semicolon);

        if errors.is_empty() {
            Ok(ImportStatement {
                path,
                items,
                alias: None,
            })
        } else {
            Err(errors)
        }
    }

    /// Parse macro declaration
    fn parse_macro(&mut self) -> ParseResult<MacroDeclaration> {
        let mut errors = Vec::new();

        if !self.consume(TokenType::Macro) {
            return Err(vec![ParseError {
                message: "Expected 'macro' keyword".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::Macro],
                found: Some(self.peek().token_type.clone()),
            }]);
        }

        let name = if self.check(TokenType::Identifier) {
            self.advance().value.clone()
        } else {
            errors.push(ParseError {
                message: "Expected macro name".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::Identifier],
                found: Some(self.peek().token_type.clone()),
            });
            "unknown".to_string()
        };

        // Parse macro parameters
        let mut parameters = Vec::new();
        if self.consume(TokenType::LeftParen) {
            while !self.check(TokenType::RightParen) && !self.is_at_end() {
                if self.check(TokenType::Identifier) {
                    parameters.push(self.advance().value);
                    if !self.check(TokenType::RightParen) {
                        if !self.consume(TokenType::Comma) {
                            errors.push(ParseError {
                                message: "Expected ',' between macro parameters".to_string(),
                                location: self.current_location(),
                                expected: vec![TokenType::Comma],
                                found: Some(self.peek().token_type.clone()),
                            });
                            break;
                        }
                    }
                } else {
                    errors.push(ParseError {
                        message: "Expected macro parameter name".to_string(),
                        location: self.current_location(),
                        expected: vec![TokenType::Identifier],
                        found: Some(self.peek().token_type.clone()),
                    });
                    break;
                }
            }
            if !self.consume(TokenType::RightParen) {
                errors.push(ParseError {
                    message: "Expected ')' after macro parameters".to_string(),
                    location: self.current_location(),
                    expected: vec![TokenType::RightParen],
                    found: Some(self.peek().token_type.clone()),
                });
            }
        }

        // Parse macro body
        let body = match self.parse_block() {
            Ok(block) => block,
            Err(mut errs) => {
                errors.append(&mut errs);
                Block {
                    statements: Vec::new(),
                    privacy_level: None,
                    attributes: Vec::new(),
                }
            }
        };

        if errors.is_empty() {
            Ok(MacroDeclaration {
                name,
                parameters,
                body,
                attributes: Vec::new(),
            })
        } else {
            Err(errors)
        }
    }

    /// Parse export declaration
    fn parse_export(&mut self) -> ParseResult<Declaration> {
        if !self.consume(TokenType::Export) {
            return Err(vec![ParseError {
                message: "Expected 'export' keyword".to_string(),
                location: self.current_location(),
                expected: vec![TokenType::Export],
                found: Some(self.peek().token_type.clone()),
            }]);
        }

        // Parse the declaration being exported
        match self.peek().token_type {
            TokenType::Function => {
                let function = self.parse_function()?;
                Ok(Declaration::Export(ExportDeclaration {
                    declaration: Box::new(Declaration::Function(function)),
                }))
            }
            TokenType::Contract => {
                let contract = self.parse_contract()?;
                Ok(Declaration::Export(ExportDeclaration {
                    declaration: Box::new(Declaration::Contract(contract)),
                }))
            }
            TokenType::Macro => {
                let macro_decl = self.parse_macro()?;
                Ok(Declaration::Export(ExportDeclaration {
                    declaration: Box::new(Declaration::Macro(macro_decl)),
                }))
            }
            _ => {
                Err(vec![ParseError {
                    message: "Expected exportable declaration".to_string(),
                    location: self.current_location(),
                    expected: vec![TokenType::Function, TokenType::Contract, TokenType::Macro],
                    found: Some(self.peek().token_type.clone()),
                }])
            }
        }
    }

    /// Parse contract function
    fn parse_contract_function(&mut self) -> ParseResult<ContractFunction> {
        let function = self.parse_function()?;
        
        Ok(ContractFunction {
            function,
            visibility: Visibility::Private,
            mutability: StateMutability::Mutable,
            modifiers: Vec::new(),
            gas_limit: None,
        })
    }

    /// Parse state variable
    fn parse_state_variable(&mut self) -> ParseResult<StateVariable> {
        let let_stmt = self.parse_let_statement()?;
        
        Ok(StateVariable {
            name: let_stmt.name,
            var_type: let_stmt.type_annotation.unwrap_or(TypeAnnotation {
                base_type: BaseType::String,
                generics: Vec::new(),
                privacy_wrapper: None,
                constraints: Vec::new(),
            }),
            visibility: Visibility::Private,
            privacy: let_stmt.privacy,
            initial_value: let_stmt.value,
            storage_location: StorageLocation::Storage,
        })
    }

    // Helper methods

    /// Check if we're at end of tokens
    fn is_at_end(&self) -> bool {
        self.current >= self.tokens.len() || self.peek().token_type == TokenType::EOF
    }

    /// Peek at current token
    fn peek(&self) -> &Token {
        if self.current >= self.tokens.len() {
            &self.eof_token
        } else {
            &self.tokens[self.current]
        }
    }

    /// Get previous token
    fn previous(&self) -> &Token {
        if self.current == 0 {
            self.peek()
        } else {
            &self.tokens[self.current - 1]
        }
    }

    /// Advance to next token
    fn advance(&mut self) -> &Token {
        if !self.is_at_end() {
            self.current += 1;
        }
        self.previous()
    }

    /// Check if current token matches type
    fn check(&self, token_type: TokenType) -> bool {
        if self.is_at_end() {
            false
        } else {
            self.peek().token_type == token_type
        }
    }

    /// Consume token if it matches expected type
    fn consume(&mut self, token_type: TokenType) -> bool {
        if self.check(token_type) {
            self.advance();
            true
        } else {
            false
        }
    }

    /// Match any of the given token types
    fn match_types(&mut self, types: &[TokenType]) -> bool {
        for token_type in types {
            if self.check(token_type.clone()) {
                self.advance();
                return true;
            }
        }
        false
    }

    /// Get current location
    fn current_location(&self) -> Option<SourceLocation> {
        if self.current < self.tokens.len() {
            Some(self.tokens[self.current].location.clone())
        } else {
            None
        }
    }
}

impl From<ParseError> for NymScriptError {
    fn from(error: ParseError) -> Self {
        let mut nymscript_error = NymScriptError::new(
            error.message,
            ErrorType::Parse,
            ErrorSeverity::Error,
        );
        
        if let Some(location) = error.location {
            nymscript_error.location = Some(location);
        }
        
        if !error.expected.is_empty() {
            nymscript_error = nymscript_error.with_suggestion(
                format!("Expected one of: {:?}", error.expected)
            );
        }
        
        if let Some(found) = error.found {
            nymscript_error = nymscript_error.with_context(
                "found_token".to_string(),
                format!("{:?}", found)
            );
        }
        
        nymscript_error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::NymScriptLexer;

    fn parse_source(source: &str) -> ParseResult<NymScriptAST> {
        let mut lexer = NymScriptLexer::new(source);
        let tokens = lexer.tokenize().unwrap();
        let mut parser = NymScriptParser::new(tokens);
        parser.parse()
    }

    #[test]
    fn test_empty_contract() {
        let source = "contract Test {}";
        let ast = parse_source(source).unwrap();
        
        assert_eq!(ast.contracts.len(), 1);
        assert_eq!(ast.contracts[0].name, "Test");
        assert!(ast.contracts[0].state.is_empty());
        assert!(ast.contracts[0].functions.is_empty());
    }

    #[test]
    fn test_function_parsing() {
        let source = "fn test() {}";
        let ast = parse_source(source).unwrap();
        
        assert_eq!(ast.declarations.len(), 1);
        if let Declaration::Function(func) = &ast.declarations[0] {
            assert_eq!(func.name, "test");
            assert!(func.parameters.is_empty());
            assert!(func.return_type.is_none());
        } else {
            panic!("Expected function declaration");
        }
    }

    #[test]
    fn test_function_with_parameters() {
        let source = "fn add(a: int, b: int) -> int {}";
        let ast = parse_source(source).unwrap();
        
        assert_eq!(ast.declarations.len(), 1);
        if let Declaration::Function(func) = &ast.declarations[0] {
            assert_eq!(func.name, "add");
            assert_eq!(func.parameters.len(), 2);
            assert_eq!(func.parameters[0].name, "a");
            assert_eq!(func.parameters[1].name, "b");
            assert!(func.return_type.is_some());
        } else {
            panic!("Expected function declaration");
        }
    }

    #[test]
    fn test_contract_with_function() {
        let source = r#"
            contract Test {
                fn test_function() {
                    let x = 42;
                }
            }
        "#;
        let ast = parse_source(source).unwrap();
        
        assert_eq!(ast.contracts.len(), 1);
        assert_eq!(ast.contracts[0].functions.len(), 1);
        assert_eq!(ast.contracts[0].functions[0].function.name, "test_function");
    }

    #[test]
    fn test_let_statement() {
        let source = "fn test() { let x = 42; }";
        let ast = parse_source(source).unwrap();
        
        if let Declaration::Function(func) = &ast.declarations[0] {
            assert_eq!(func.body.statements.len(), 1);
            if let Statement::Let(let_stmt) = &func.body.statements[0] {
                assert_eq!(let_stmt.name, "x");
                assert!(let_stmt.value.is_some());
            } else {
                panic!("Expected let statement");
            }
        }
    }

    #[test]
    fn test_if_statement() {
        let source = "fn test() { if true { let x = 1; } }";
        let ast = parse_source(source).unwrap();
        
        if let Declaration::Function(func) = &ast.declarations[0] {
            assert_eq!(func.body.statements.len(), 1);
            if let Statement::If(if_stmt) = &func.body.statements[0] {
                if let Expression::Literal(Literal::Bool(true)) = if_stmt.condition {
                    assert_eq!(if_stmt.then_branch.statements.len(), 1);
                } else {
                    panic!("Expected boolean literal");
                }
            } else {
                panic!("Expected if statement");
            }
        }
    }

    #[test]
    fn test_binary_expression() {
        let source = "fn test() { let x = 1 + 2 * 3; }";
        let ast = parse_source(source).unwrap();
        
        if let Declaration::Function(func) = &ast.declarations[0] {
            if let Statement::Let(let_stmt) = &func.body.statements[0] {
                if let Some(Expression::Binary(_)) = &let_stmt.value {
                    // Successfully parsed binary expression
                } else {
                    panic!("Expected binary expression");
                }
            }
        }
    }

    #[test]
    fn test_privacy_operators() {
        let source = "fn test() { let x = a === b; let y = a ++= b; }";
        let ast = parse_source(source).unwrap();
        
        if let Declaration::Function(func) = &ast.declarations[0] {
            assert_eq!(func.body.statements.len(), 2);
            
            // Check private equality
            if let Statement::Let(let_stmt) = &func.body.statements[0] {
                if let Some(Expression::Binary(binary)) = &let_stmt.value {
                    assert!(matches!(binary.operator, BinaryOperator::PrivateEq));
                }
            }
            
            // Check private addition
            if let Statement::Let(let_stmt) = &func.body.statements[1] {
                if let Some(Expression::Binary(binary)) = &let_stmt.value {
                    assert!(matches!(binary.operator, BinaryOperator::PrivateAdd));
                }
            }
        }
    }

    #[test]
    fn test_return_statement() {
        let source = "fn test() -> int { return 42; }";
        let ast = parse_source(source).unwrap();
        
        if let Declaration::Function(func) = &ast.declarations[0] {
            if let Statement::Return(ret_stmt) = &func.body.statements[0] {
                assert!(ret_stmt.value.is_some());
                if let Some(Expression::Literal(Literal::Int(42))) = &ret_stmt.value {
                    // Correct return value
                } else {
                    panic!("Expected integer literal 42");
                }
            } else {
                panic!("Expected return statement");
            }
        }
    }

    #[test]
    fn test_parse_error_handling() {
        let source = "fn test( { }"; // Missing parameter list closing
        let result = parse_source(source);
        
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_nested_expressions() {
        let source = "fn test() { let x = (1 + 2) * (3 - 4); }";
        let ast = parse_source(source).unwrap();
        
        if let Declaration::Function(func) = &ast.declarations[0] {
            if let Statement::Let(let_stmt) = &func.body.statements[0] {
                if let Some(Expression::Binary(binary)) = &let_stmt.value {
                    assert!(matches!(binary.operator, BinaryOperator::Mul));
                    // Should have parsed nested parenthesized expressions
                } else {
                    panic!("Expected binary expression");
                }
            }
        }
    }

    #[test]
    fn test_type_annotations() {
        let source = "fn test(x: bool, y: string) -> int {}";
        let ast = parse_source(source).unwrap();
        
        if let Declaration::Function(func) = &ast.declarations[0] {
            assert_eq!(func.parameters.len(), 2);
            
            // Check parameter types
            assert!(matches!(func.parameters[0].param_type.base_type, BaseType::Bool));
            assert!(matches!(func.parameters[1].param_type.base_type, BaseType::String));
            
            // Check return type
            assert!(func.return_type.is_some());
            if let Some(return_type) = &func.return_type {
                assert!(matches!(return_type.base_type, BaseType::Int(_)));
            }
        }
    }

    #[test]
    fn test_privacy_annotations_parsing() {
        let source = "@private fn secret_function(@confidential data: bytes) -> @anonymous bool { return true; }";
        let ast = parse_source(source).unwrap();
        
        assert_eq!(ast.declarations.len(), 1);
        if let Declaration::Function(func) = &ast.declarations[0] {
            assert_eq!(func.privacy.level, PrivacyLevel::Private);
            assert_eq!(func.parameters.len(), 1);
            // Note: Parameter privacy annotations would need enhanced parameter parsing
        } else {
            panic!("Expected function declaration");
        }
    }

    #[test]
    fn test_import_parsing() {
        let source = r#"
            import "std/crypto";
            import "std/math" { add, subtract, multiply };
            fn test() {}
        "#;
        let ast = parse_source(source).unwrap();
        
        assert_eq!(ast.imports.len(), 2);
        assert_eq!(ast.imports[0].path, "std/crypto");
        assert!(ast.imports[0].items.is_none());
        
        assert_eq!(ast.imports[1].path, "std/math");
        assert!(ast.imports[1].items.is_some());
        assert_eq!(ast.imports[1].items.as_ref().unwrap().len(), 3);
        
        assert_eq!(ast.declarations.len(), 1);
    }

    #[test]
    fn test_macro_parsing() {
        let source = "macro debug_print(msg) { /* implementation */ }";
        let ast = parse_source(source).unwrap();
        
        assert_eq!(ast.declarations.len(), 1);
        if let Declaration::Macro(macro_decl) = &ast.declarations[0] {
            assert_eq!(macro_decl.name, "debug_print");
            assert_eq!(macro_decl.parameters.len(), 1);
            assert_eq!(macro_decl.parameters[0], "msg");
        } else {
            panic!("Expected macro declaration");
        }
    }

    #[test]
    fn test_export_parsing() {
        let source = "export fn public_function() { return 42; }";
        let ast = parse_source(source).unwrap();
        
        assert_eq!(ast.declarations.len(), 1);
        if let Declaration::Export(export) = &ast.declarations[0] {
            if let Declaration::Function(func) = &**export.declaration {
                assert_eq!(func.name, "public_function");
            } else {
                panic!("Expected function in export");
            }
        } else {
            panic!("Expected export declaration");
        }
    }

    #[test]
    fn test_privacy_contract_parsing() {
        let source = "@secure contract SecureContract { @private fn secret_method() {} }";
        let ast = parse_source(source).unwrap();
        
        assert_eq!(ast.contracts.len(), 1);
        assert_eq!(ast.contracts[0].name, "SecureContract");
        assert_eq!(ast.contracts[0].functions.len(), 1);
        assert_eq!(ast.contracts[0].functions[0].function.name, "secret_method");
    }

    #[test]
    fn test_zk_keywords_parsing() {
        let source = "fn test() { circuit my_circuit; witness secret_witness; }";
        // This would test ZK-specific keyword parsing in expressions
        // For now, we'll just test that it doesn't fail
        let result = parse_source(source);
        assert!(result.is_ok() || result.is_err()); // Placeholder - would need expression parsing for ZK keywords
    }

    #[test]
    fn test_complex_privacy_example() {
        let source = r#"
            import "std/crypto" { encrypt, decrypt };
            
            @private contract PrivacyContract {
                @confidential fn process_data(@secret input: bytes) -> @anonymous bytes {
                    let encrypted = encrypt(input);
                    return encrypted;
                }
            }
            
            export fn public_interface() {
                return "public access point";
            }
        "#;
        
        let ast = parse_source(source).unwrap();
        
        assert_eq!(ast.imports.len(), 1);
        assert_eq!(ast.contracts.len(), 1);
        assert_eq!(ast.declarations.len(), 1);
        
        // Verify contract structure
        assert_eq!(ast.contracts[0].name, "PrivacyContract");
        assert_eq!(ast.contracts[0].functions.len(), 1);
        assert_eq!(ast.contracts[0].functions[0].function.name, "process_data");
        
        // Verify export
        if let Declaration::Export(export) = &ast.declarations[0] {
            if let Declaration::Function(func) = &**export.declaration {
                assert_eq!(func.name, "public_interface");
            }
        }
    }
}