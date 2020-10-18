#ifndef EXPR3_H
#define EXPR3_H

#include <string>
#include <vector>
#include <algorithm>

#include <QtGlobal>
#include <QString>


/*
  Implements and expression evaluatoin engine with the shunting yard algorithm.
  Complexity: O(n), n = length of expression.

  Can handle binary and unary operators, parentheses, variables, functions, composite functions, var-arg functions.
  Expressions can be pre-compiled for quicker evaluation.
  Variables are resolved via a context.
  Operator precedence follows the C++ specification.

  Resources:
  https://en.cppreference.com/w/cpp/language/operator_precedence
  https://en.wikipedia.org/wiki/Shunting-yard_algorithm
  http://reedbeta.com/blog/the-shunting-yard-algorithm/
*/


namespace expr3 {



class Token;
class expr_eval_context
{
public:
    virtual ~expr_eval_context() = default;
    virtual Token resolve_var_if_needed(const Token& var) =0;
    virtual bool assign(const Token& dest, const Token& val) =0;
    virtual Token exec_function(const Token& func, std::vector<Token>& args) =0;
};



class Token {
public:
    enum class Type {
        Unknown = 0,
        Number,
        Function,
        FuncArgSeparator,
        Error,

        StrConstant,

        left_round_brace,   // (
        right_round_brace,  // )
        left_edge_brace,    // [
        right_edge_brace,   // ]
        comma,              // ,

        op_assign,          // =

        op_equal,           // ==
        op_not_equal,       // !=

        op_plus,            // +
        op_minus,           // -
        op_div,             // /
        op_mul,             // *
        op_bin_not,         // ~

        op_logical_not,     // !
        op_remainder,       // %
        op_logical_and,     // &&
        op_logical_or,      // ||
        op_binary_and,      // &
        op_binary_or,       // |
        op_binary_xor,      // ^

        op_cmd_small,       //<
        op_cmd_shl,         //<<
        op_cmd_rol,         //<<<
        op_cmd_smalleq,     //<=
        op_cmd_assign_shl,  //<<=
        op_cmd_assign_rol,  //<<<=

        op_cmd_big,         //>
        op_cmd_shr,         //>>
        op_cmd_ror,         //>>>
        op_cmd_bigeq,       //>=
        op_cmd_assign_shr,  //>>=
        op_cmd_assign_ror,  //>>>=

        op_assign_plus,       // +=
        op_assign_minus,      // -=
        op_assign_mul,        // *=
        op_assign_div,        // /=
        op_assign_remainder,  // %=
        op_assign_binary_and, // &=
        op_assign_binary_or,  // |=
        op_assign_binary_xor, // ^=


        op_assign_logical_and, // doesnt exist in C++/Java and is not implemented!
        op_assign_logical_or,  // doesnt exist in C++/Java and is not implemented!
        op_max,
    };

    enum class associativity {
        unknown_assoc = 0,
        right_assoc,
        left_assoc,
    };

    enum class op_type {
        unknown = 0,
        unary,
        binary,
    };

    using integer_type = quint64;

    Type type = Type::Unknown;
    op_type op_kind = op_type::unknown;
    QString str;
    int precedence = -1;
    int size = 0;
    associativity assoc = associativity::unknown_assoc;
    qint32 default_base = 16;

    Token() = default;
    Token(Type t, const QString& s, int prec = -1, associativity ass = associativity::unknown_assoc)
        : type { t }, str ( s ), precedence { prec }, assoc { ass }
    {
    }
    Token(integer_type val)
    {
        type = Type::Number;
        str = QString::number(val, default_base);
    }

    static Token make_error(QString msg)
    {
        return Token(Type::Error, msg);
    }

    static Token make_constant(integer_type val)
    {
        return Token(Type::Number, QString::number(val, 16));
    }

    bool is_function() const { return type == Type::Function; }
    bool is_comma()    const { return type == Type::comma; }
    bool is_string()   const { return type == Type::StrConstant; }
    bool is_error()    const { return type == Type::Error; }
    bool is_valid()    const { return type != Type::Unknown && !is_error(); }

    bool is_left_associative()  const { return assoc == associativity::left_assoc;  }
    bool is_right_associative() const { return assoc == associativity::right_assoc; }

    bool is_op() const
    {
        switch(type)
        {
            case Type::op_equal: case Type:: op_not_equal:
            case Type::op_plus:  case Type::op_minus: case Type::op_mul: case Type::op_div: case Type::op_remainder:

            case Type::op_bin_not:     case Type::op_logical_not:
            case Type::op_logical_and: case Type::op_logical_or:
            case Type::op_binary_and:  case Type::op_binary_or:  case Type::op_binary_xor:

            case Type::op_cmd_small: case Type::op_cmd_shl: case Type::op_cmd_rol:case Type::op_cmd_smalleq:
            case Type::op_cmd_big:   case Type::op_cmd_shr: case Type::op_cmd_ror:case Type::op_cmd_bigeq:

            case Type::op_assign:
            case Type::op_cmd_assign_ror:     case Type::op_cmd_assign_shr:
            case Type::op_cmd_assign_rol:     case Type::op_cmd_assign_shl:
            case Type::op_assign_plus:        case Type::op_assign_minus:
            case Type::op_assign_mul:         case Type::op_assign_div:
            case Type::op_assign_remainder:   case Type::op_assign_binary_and:
            case Type::op_assign_binary_or:   case Type::op_assign_binary_xor:
                return true;
            default:
                return false;
        }
    }

    bool is_op_binary() const
    {
        return op_kind == op_type::binary;
    }

    bool is_op_unary() const
    {
        return op_kind == op_type::unary;
    }

    integer_type as_integer() const
    {
        integer_type val;
        if(is_constant(&val))
            return val;
        return 0;
    }

    //todo! toULongLong doesnt consider integer_type signedness!
    bool is_constant(integer_type* out = nullptr) const
    {
        bool ok;
        auto val = str.toULongLong(&ok, default_base);
        if(ok && out)
            *out = val;
        if(!ok)
        {
            val = str.toULongLong(&ok, 16);
            if(ok && out)
                *out = val;
            if(!ok)
            {
                val = str.toULongLong(&ok, 10);
                if(ok && out)
                    *out = val;
            }
        }
        return ok;
    }

    //https://en.cppreference.com/w/cpp/language/operator_precedence
    static Token create_from_type(Type t)
    {
        const auto left  = associativity::left_assoc;
        const auto right = associativity::right_assoc;
        switch(t)
        {

            case Type::op_bin_not:          return Token(t, "~",     3, right);
            case Type::op_logical_not:      return Token(t, "!",     3, right);

            case Type::op_binary_and:       return Token(t, "&",     11, left);
            case Type::op_binary_xor:       return Token(t, "^",     12, left);
            case Type::op_binary_or:        return Token(t, "|",     13, left);
            case Type::op_logical_and:      return Token(t, "&&",    14, left);
            case Type::op_logical_or:       return Token(t, "||",    15, left);

            case Type::op_equal:            return Token(t, "==",   10, left);
            case Type::op_not_equal:        return Token(t, "!=",   10, left);
            case Type::op_plus:             return Token(t, "+",     6, left);
            case Type::op_minus:            return Token(t, "-",     6, left);
            case Type::op_mul:              return Token(t, "*",     5, left);
            case Type::op_div:              return Token(t, "/",     5, left);
            case Type::op_remainder:        return Token(t, "%",     5, left);

            case Type::op_cmd_shl:          return Token(t, "<<",    7, left);
            case Type::op_cmd_rol:          return Token(t, "<<<",   7, left);
            case Type::op_cmd_small:        return Token(t, "<",     9, left);
            case Type::op_cmd_smalleq:      return Token(t, "<=",    9, right);

            case Type::op_cmd_shr:          return Token(t, ">>",    7, left);
            case Type::op_cmd_ror:          return Token(t, ">>>",   7, left);
            case Type::op_cmd_big:          return Token(t, ">",     9, left);
            case Type::op_cmd_bigeq:        return Token(t, ">=",    9, right);

            case Type::op_assign:           return Token(t, "=",    16, right);
            case Type::op_cmd_assign_shl:   return Token(t, "<<=",  16, right);
            case Type::op_cmd_assign_rol:   return Token(t, "<<<=", 16, right);
            case Type::op_cmd_assign_shr:   return Token(t, ">>=",  16, right);
            case Type::op_cmd_assign_ror:   return Token(t, ">>>=", 16, right);
            case Type::op_assign_plus:      return Token(t, "+=",   16, right);
            case Type::op_assign_minus:     return Token(t, "-=",   16, right);
            case Type::op_assign_mul:       return Token(t, "*=",   16, right);
            case Type::op_assign_div:       return Token(t, "/=",   16, right);
            case Type::op_assign_remainder: return Token(t, "%=",   16, right);
            case Type::op_assign_binary_and:return Token(t, "&=",   16, right);
            case Type::op_assign_binary_or: return Token(t, "|=",   16, right);
            case Type::op_assign_binary_xor:return Token(t, "^=",   16, right);

            case Type::left_round_brace:    return Token(t, "(",    -1, left);
            case Type::right_round_brace:   return Token(t, ")",    -1, left);
            case Type::left_edge_brace:     return Token(t, "[",    -1, left);
            case Type::right_edge_brace:    return Token(t, "]",    -1, left);
            case Type::comma:               return Token(t, ",",    17, left);
            case Type::FuncArgSeparator:    return Token(t, "#");
            default:
                return Token();
        }
    }

    /*
     Evaluates two constants according to operator op.
     */
    static Token eval_op(Token::Type op, Token left, Token right, expr_eval_context* context)
    {
        const Token original_left = left;

        //assert(context != nullptr)
        if(left.is_valid())
            left  = context->resolve_var_if_needed(left);
        if(right.is_valid())
            right = context->resolve_var_if_needed(right);

        Token evaluated;
        switch(op)
        {
            case Type::StrConstant:
            case Type::Number:
            case Type::left_round_brace:
            case Type::right_round_brace:
            case Type::left_edge_brace:
            case Type::right_edge_brace:
            default:
                return {};
            case Type::op_logical_and:      return left.as_integer() && right.as_integer();
            case Type::op_logical_or:       return left.as_integer() || right.as_integer();
            case Type::op_binary_and:       return left.as_integer() & right.as_integer();
            case Type::op_binary_or:        return left.as_integer() | right.as_integer();
            case Type::op_binary_xor:       return left.as_integer() ^ right.as_integer();
            case Type::op_equal:            return integer_type(left.as_integer() == right.as_integer());
            case Type::op_not_equal:        return integer_type(left.as_integer() != right.as_integer());
            case Type::op_bin_not:          return left.as_integer() * 2;
            case Type::op_logical_not:      return integer_type(!left.as_integer());
            case Type::op_plus:             return left.as_integer() + right.as_integer();
            case Type::op_minus:            return left.as_integer() - right.as_integer();
            case Type::op_div:              return left.as_integer() / right.as_integer();
            case Type::op_mul:              return left.as_integer() * right.as_integer();
            case Type::op_remainder:        return left.as_integer() % right.as_integer();
            case Type::op_cmd_small:        return integer_type(left.as_integer() < right.as_integer());
            case Type::op_cmd_shl:          return left.as_integer() << right.as_integer();
            case Type::op_cmd_rol:          return left.as_integer() << right.as_integer(); //todo rol
            case Type::op_cmd_smalleq:      return integer_type(left.as_integer() <= right.as_integer());
            case Type::op_cmd_big:          return integer_type(left.as_integer() > right.as_integer());
            case Type::op_cmd_shr:          return left.as_integer() >> right.as_integer();
            case Type::op_cmd_ror:          return left.as_integer() >> right.as_integer(); //todo ror
            case Type::op_cmd_bigeq:        return integer_type(left.as_integer() >= right.as_integer());

            case Type::op_assign:             evaluated = right.as_integer();                       break;
            case Type::op_cmd_assign_shl:     evaluated = left.as_integer() << right.as_integer();  break;
            case Type::op_cmd_assign_rol:     evaluated = left.as_integer() * right.as_integer();   break; //todo rol
            case Type::op_cmd_assign_shr:     evaluated = left.as_integer() >> right.as_integer();  break;
            case Type::op_cmd_assign_ror:     evaluated = left.as_integer() * right.as_integer();   break; //todo ror
            case Type::op_assign_plus:        evaluated = left.as_integer() + right.as_integer();   break;
            case Type::op_assign_minus:       evaluated = left.as_integer() - right.as_integer();   break;
            case Type::op_assign_mul:         evaluated = left.as_integer() * right.as_integer();   break;
            case Type::op_assign_div:         evaluated = left.as_integer() / right.as_integer();   break;
            case Type::op_assign_remainder:   evaluated = left.as_integer() % right.as_integer();   break;
            case Type::op_assign_binary_and:  evaluated = left.as_integer() & right.as_integer();   break;
            case Type::op_assign_binary_or:   evaluated = left.as_integer() | right.as_integer();   break;
            case Type::op_assign_binary_xor:  evaluated = left.as_integer() ^ right.as_integer();   break;
        }

        //assert(target.is_valid())
        if(!context->assign(original_left, evaluated))
            return Token::make_error("error during assignment"); //err |= error_type::assignment_error;
        return original_left;
    }
};





class default_expr_eval_context : public expr_eval_context
{
public:
    Token resolve_var_if_needed(const Token& var) override
    {
        return var;
    }
    bool assign(const Token& dest, const Token& val) override
    {
        Q_UNUSED(dest);
        Q_UNUSED(val);
        return true;
    }
    Token exec_function(const Token& func, std::vector<Token>& args) override
    {
        if(func.type != Token::Type::Function)
            return {};

        if(func.str == "__deref")
        {
            if(args.empty())
                return {};
            int size = func.size;
            if(size == -1)
            {
                size = 4; //todo: select right one...
            }
            auto adr = args.back().as_integer();
            Q_UNUSED(adr);
            //memread(adr,tok.size)
            return Token::make_constant(0x33333333);
        }
        else if(func.str == "max")
        {
            if(args.size() < 2)
                return false;

            Token op1 = args[0];
            Token op2 = args[1];

            Token res = Token::make_constant(std::max(op1.as_integer(), op2.as_integer()));
            return res;
        }

        return {};
    }
};


class expr3
{
    enum error_type {
        no_error = 0,
        parens_mismatch = 1,
        operator_mismatch = 2,
        other_error = 4,
        internal_error = 8,
        eval_stack_error = 16,
        function_or_deref_error = 32,
        assignment_error = 64,
    };

    std::vector<Token> data;
    QString expr;

public:
    expr3() = default;
    expr3(const QString& expression)
    {
        set_from_string(expression);
    }

    Token set_from_string(const QString& expression)
    {
        expr = expression;
        data = tokenize(expr.toStdString());
        pre_process(data);
        data = shunting_yard(data);
        if(data.size() && data.back().is_error())
        {
            Token r = data.back();
            data.clear();
            return r;
        }
        return data.empty();
    }

    QString intermediate_repr() const
    {
        QString r;
        for(const auto& t : data)
            r += t.str + ' ';
        return r;
    }

    QString string_repr() const
    {
        return expr;
    }

    Token::integer_type eval(expr_eval_context* context = nullptr) const
    {
        default_expr_eval_context dc;
        if(context == nullptr)
            context = &dc;
        return eval(data, context).as_integer();
    }

    static std::vector<Token> tokenize(const std::string& str)
    {
        std::vector<Token> tokens;

        const auto peek_grab_char_if = [&](size_t& i, char c) {
            if(i+1 < str.length())
            {
                if(str[i+1] == c)
                {
                    i++;
                    return true;
                }
            }
            return false;
        };

        bool grab_string = false;
        QString cur_data;

        const auto add_operator = [&](Token::Type t) {
            if(cur_data.size())
            {
                tokens.push_back(Token(Token::Type::Number, cur_data));
                cur_data.clear();
            }
            tokens.push_back(Token::create_from_type(t));
        };

        for(size_t i = 0; i < str.size(); i++)
        {
            const char ch = str.at(i);
            if(ch == '"')
            {
                if(grab_string)
                {
                    tokens.push_back(Token(Token::Type::StrConstant, cur_data));
                    cur_data.clear();
                }
                grab_string = !grab_string;
            }
            else if(grab_string)
            {
                cur_data.push_back(ch);
            }
            else if(ch == ' ')
            {
                if(cur_data.size())
                {
                    tokens.push_back(Token(Token::Type::Number, cur_data));
                    cur_data.clear();
                }
            }
            else
            {
                switch(ch)
                {
                    default:  cur_data.push_back(ch); break;

                    case '+':
                        if(peek_grab_char_if(i, '='))
                            add_operator(Token::Type::op_assign_plus);
                        else
                            add_operator(Token::Type::op_plus);
                        break;
                    case '-':
                        if(peek_grab_char_if(i, '='))
                            add_operator(Token::Type::op_assign_minus);
                        else
                            add_operator(Token::Type::op_minus);
                        break;
                    case '*':
                        if(peek_grab_char_if(i, '='))
                            add_operator(Token::Type::op_assign_mul);
                        else
                            add_operator(Token::Type::op_mul);
                        break;
                    case '/':
                        if(peek_grab_char_if(i, '='))
                            add_operator(Token::Type::op_assign_div);
                        else
                            add_operator(Token::Type::op_div);
                        break;
                    case '%':
                        if(peek_grab_char_if(i, '='))
                            add_operator(Token::Type::op_assign_remainder);
                        else
                            add_operator(Token::Type::op_remainder);
                        break;
                    case '^':
                        if(peek_grab_char_if(i, '='))
                            add_operator(Token::Type::op_assign_binary_xor);
                        else
                            add_operator(Token::Type::op_binary_xor);
                        break;
                    case '~': add_operator(Token::Type::op_bin_not);        break;
                    case '(': add_operator(Token::Type::left_round_brace);  break;
                    case ')': add_operator(Token::Type::right_round_brace); break;
                    case '[': add_operator(Token::Type::left_edge_brace);   break;
                    case ']': add_operator(Token::Type::right_edge_brace);  break;
                    case ',': add_operator(Token::Type::comma);             break;
                    case '|':
                        if(peek_grab_char_if(i, '='))
                            add_operator(Token::Type::op_assign_binary_or); // |=
                        else
                            add_operator(Token::Type::op_binary_or);
                        break;
                    case '&':
                        if(peek_grab_char_if(i, '='))
                            add_operator(Token::Type::op_assign_binary_and); // &=
                        else
                            add_operator(Token::Type::op_binary_and);
                        break;
                    case '=':
                        if(peek_grab_char_if(i, '='))
                            add_operator(Token::Type::op_equal);
                        else
                            add_operator(Token::Type::op_assign);
                        break;
                    case '!':
                        if(peek_grab_char_if(i, '='))
                            add_operator(Token::Type::op_not_equal);
                        else
                            add_operator(Token::Type::op_logical_not);
                        break;
                    case '<':
                        if(peek_grab_char_if(i, '<'))
                        {
                            if(peek_grab_char_if(i, '<'))
                            {
                                if(peek_grab_char_if(i, '='))
                                    add_operator(Token::Type::op_cmd_assign_rol);
                                else
                                    add_operator(Token::Type::op_cmd_rol);
                            }
                            else
                            {
                                if(peek_grab_char_if(i, '='))
                                    add_operator(Token::Type::op_cmd_assign_shl);
                                else
                                    add_operator(Token::Type::op_cmd_shl);
                            }
                        }
                        else
                        {
                            if(peek_grab_char_if(i, '='))
                                add_operator(Token::Type::op_cmd_smalleq);
                            else
                                add_operator(Token::Type::op_cmd_small);
                        }
                        break;
                    case '>':
                        if(peek_grab_char_if(i, '>'))
                        {
                            if(peek_grab_char_if(i, '>'))
                            {
                                if(peek_grab_char_if(i, '='))
                                    add_operator(Token::Type::op_cmd_assign_ror);
                                else
                                    add_operator(Token::Type::op_cmd_ror);
                            }
                            else
                            {
                                if(peek_grab_char_if(i, '='))
                                    add_operator(Token::Type::op_cmd_assign_shr);
                                else
                                    add_operator(Token::Type::op_cmd_shr);
                            }
                        }
                        else
                        {
                            if(peek_grab_char_if(i, '='))
                                add_operator(Token::Type::op_cmd_bigeq);
                            else
                                add_operator(Token::Type::op_cmd_big);
                        }
                        break;
                }
            }
        }

        if(cur_data.size())
        {
            tokens.push_back(Token(Token::Type::Number, cur_data));
            cur_data.clear();
        }
        return tokens;
    }

    static void pre_process(std::vector<Token>& tokens)
    {
        //size qualifiers
        //patch [] deref accessor with __deref() function call
        for(size_t i=1; i < tokens.size(); i++)
        {
            if(tokens[i].type == Token::Type::left_edge_brace)
            {
                tokens[i] = Token::create_from_type(Token::Type::left_round_brace);
                if(tokens[i-1].type == Token::Type::Number)
                {
                    const QString str = tokens[i-1].str.toLower();
                    if(str == "byte")
                        tokens[i-1].size = 1;
                    else if(str == "word")
                        tokens[i-1].size = 2;
                    else if(str == "dword")
                        tokens[i-1].size = 4;
                    else if(str == "qword")
                        tokens[i-1].size = 8;

                    tokens[i-1].type = Token::Type::Function;
                    tokens[i-1].str = "__deref";
                }
                else
                {
                    //we have to insert a size qualifier
                    Token t(Token::Type::Function, "__deref");
                    t.size = -1;
                    tokens.insert(tokens.begin() + int(i), t);
                }
            }
            else if(tokens[i].type == Token::Type::right_edge_brace)
            {
                tokens[i] = Token::create_from_type(Token::Type::right_round_brace);
            }
        }

        //function call vs. simple parens
        for(size_t i=0; i < tokens.size(); i++)
        {
            if(tokens[i].type == Token::Type::Number && !tokens[i].is_constant() && i != tokens.size()-1)
                if(tokens[i+1].type == Token::Type::left_round_brace)
                    tokens[i].type = Token::Type::Function;
        }

        //binary vs. unary op
        for(size_t i=0; i < tokens.size(); i++)
        {
            Token& tok = tokens[i];
            if(tok.is_op())
            {
                if(i == 0)
                    tok.op_kind = Token::op_type::unary; //if nothing before -> unary
                else if(tokens[i-1].type == Token::Type::Number)
                    tok.op_kind = Token::op_type::binary; // if number before -> binary
                else if(tokens[i-1].type == Token::Type::right_round_brace)
                    tok.op_kind = Token::op_type::binary; // if closing/right parens -> binary
                else
                    tok.op_kind = Token::op_type::unary;// if any other operator or open/left parens -> unary
            }
        }

        tokens.erase(std::remove_if(tokens.begin(), tokens.end(),
                [](const Token& o) { return !o.is_valid(); }),
            tokens.end());
    }

    static std::vector<Token> shunting_yard(const std::vector<Token>& tokens)
    {
        std::vector<Token> stack, output;
        stack.reserve(tokens.size());
        output.reserve(tokens.size());
        uint err=0;

        for(const auto& tok : tokens)
        {
            if(tok.type == Token::Type::Function)
            {
                output.push_back(Token::create_from_type(Token::Type::FuncArgSeparator));
                stack.push_back(tok);
            }
            else if(tok.type == Token::Type::Number)
            {
                output.push_back(tok);
            }
            else if(tok.type == Token::Type::comma)
            {
                while(stack.size() && stack.back().type != Token::Type::left_round_brace)
                {
                    output.push_back(stack.back());
                    stack.pop_back();
                }
                //output.push_back(tok);
            }
            else if(tok.is_op())
            {
                while(stack.size()
                      && ((stack.back().precedence < tok.precedence)
                          || (stack.back().precedence == tok.precedence && stack.back().is_left_associative())
                          || stack.back().type == Token::Type::Function)
                      && (stack.back().type != Token::Type::left_round_brace))
                {
                    if(tok.is_op_unary() && stack.back().is_op_binary()) //a unary operator never pops a binary one!
                        break;
                    output.push_back(stack.back());
                    stack.pop_back();
                }
                stack.push_back(tok);
            }
            else if(tok.type == Token::Type::left_round_brace)
            {
                stack.push_back(tok);
            }
            else if(tok.type == Token::Type::right_round_brace)
            {
                while(stack.size() && stack.back().type != Token::Type::left_round_brace)
                {
                    output.push_back(stack.back());
                    stack.pop_back();
                }

                if(stack.size() == 0)
                {
                    //error mismatching parens
                    err |= error_type::parens_mismatch;
                    return { Token::make_error("Parens mismatch.") };
                }

                stack.pop_back(); //remove ( from stack

                //if it was a function call, push function to output
                if(stack.size() && stack.back().type == Token::Type::Function)
                {
                    output.push_back(stack.back());
                    stack.pop_back();
                }
            }
        }

        while(stack.size())
        {
            if(stack.back().type == Token::Type::left_round_brace || stack.back().type == Token::Type::right_round_brace)
            {
                //error mismatching ( or )
                err |= error_type::parens_mismatch;
                return { Token::make_error("Parens mismatch.") };
            }
            output.push_back(stack.back());
            stack.pop_back();
        }

        return output;
    }

    static Token eval(const std::vector<Token>& expr, expr_eval_context* context)
    {
        std::vector<Token> stack;
        uint err=0;

        for(const auto& tok : expr)
        {
            if(tok.type == Token::Type::Function)
            {
                std::vector<Token> args;
                while(stack.size() && stack.back().type != Token::Type::FuncArgSeparator)
                {
                    //evaluate the variables, this also means we always pass by (evaluated) value, not reference
                    Token t = context->resolve_var_if_needed(stack.back());
                    args.push_back(t);
                    stack.pop_back();
                }
                if(stack.size() == 0)
                {
                    //error: func arg separator not found! internal error!
                    err |= error_type::internal_error;
                    return Token::make_error("Internal error. func_arg_sep not found.");
                }
                stack.pop_back(); //remove func arg separator

                //execute function
                std::reverse(args.begin(), args.end()); //stack order -> logical order

                Token r = context->exec_function(tok, args);
                if(!r.is_valid())
                {
                    err |= error_type::function_or_deref_error;
                    return Token::make_error("Error in function or on dereferencing.");
                }
                stack.push_back(r); //set return value
            }
            else if(tok.is_op())
            {
                /*
                 evaluation of the variables is done inside Token::eval_op so we can handle assignments more cleanly
                */
                if(tok.is_op_binary())
                {
                    if(stack.size() < 2)
                    {
                        //error, not possible
                        err |= error_type::eval_stack_error;
                        return Token::make_error("Stack depth error on binary operator.");
                    }

                    const Token op1 = stack.back();
                    stack.pop_back();
                    const Token op2 = stack.back();
                    stack.pop_back();

                    Token res = Token::eval_op(tok.type, op1, op2, context);
                    stack.push_back(res);
                }
                else if(tok.is_op_unary())
                {
                    if(stack.size() < 1)
                    {
                        //error, not possible
                        err |= error_type::eval_stack_error;
                        return Token::make_error("Stack depth error on unary operator.");
                    }

                    const Token op1 = stack.back();
                    stack.pop_back();
                    const Token op2 = {};

                    Token res = Token::eval_op(tok.type, op1, op2, context);
                    stack.push_back(res);
                }
            }
            else
            {
                stack.push_back(tok);
            }
        }

        if(stack.size() != 1)
        {
            //error
            err |= error_type::eval_stack_error;
            return Token::make_error("Stack depth error on finalization.");
        }

        Token final = context->resolve_var_if_needed(stack.back());
        return final;
    }
};


} //namespace expr3





#endif // EXPR3_H
