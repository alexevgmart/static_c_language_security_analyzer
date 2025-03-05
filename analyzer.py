#!/mnt/c/Users/Alexander/Desktop/static_c_language_security_analyzer/env/bin/python3
import clang.cindex
import re

sizes = {
    # Стандартные типы
    "char": 1,
    "signed char": 1,
    "unsigned char": 1,
    "short": 2,
    "unsigned short": 2,
    "int": 4,
    "unsigned int": 4,
    "long": 8,  # Зависит от платформы
    "unsigned long": 8,  # Зависит от платформы
    "long long": 8,
    "unsigned long long": 8,
    "float": 4,
    "double": 8,
    "long double": 16,  # Зависит от платформы

    # Типы из <stdint.h>
    "int8_t": 1,
    "uint8_t": 1,
    "int16_t": 2,
    "uint16_t": 2,
    "int32_t": 4,
    "uint32_t": 4,
    "int64_t": 8,
    "uint64_t": 8,
    "int_least8_t": 1,
    "uint_least8_t": 1,
    "int_least16_t": 2,
    "uint_least16_t": 2,
    "int_least32_t": 4,
    "uint_least32_t": 4,
    "int_least64_t": 8,
    "uint_least64_t": 8,
    "int_fast8_t": 1,
    "uint_fast8_t": 1,
    "int_fast16_t": 2,
    "uint_fast16_t": 2,
    "int_fast32_t": 4,
    "uint_fast32_t": 4,
    "int_fast64_t": 8,
    "uint_fast64_t": 8,
    "intmax_t": 8,
    "uintmax_t": 8,

    # Типы для указателей
    "intptr_t": 8,  # Зависит от платформы
    "uintptr_t": 8,  # Зависит от платформы
    "size_t": 8,  # Зависит от платформы
    "ptrdiff_t": 8,  # Зависит от платформы

    # Типы из <wchar.h> и <uchar.h>
    "wchar_t": 4,  # Зависит от платформы (обычно 4 байта на Linux, 2 байта на Windows)
    "char16_t": 2,  # UTF-16 (фиксированный размер)
    "char32_t": 4,  # UTF-32 (фиксированный размер)
    "wint_t": 4,  # Зависит от платформы (обычно совпадает с wchar_t)
}

read_functions = [
    'read',
    'fread',
    'scanf',
    'fscanf',
    '__isoc99_scanf',
    'gets',
    'fgets',
    'getline'
]

write_functions = [
    'write',
    'fwrite',
    'printf',
    'fprintf',
    'puts',
    'fputs'
]

# Укажите путь к libclang.so
clang.cindex.Config.set_library_file("./libclang.so") # спионерил с виртуалки на которой работал код

tu = None
found_something = False


def search_clang_parser_type(node):
    count = 0
    while True:
        for i in node.get_children():
            node = i
            if i.kind != clang.cindex.CursorKind.UNEXPOSED_EXPR:
                return i
        count += 1
        if count == 10:
            return None

def get_variable_size(variable):
    try:
        if variable.type.get_pointee().get_size() == -1:
            node = list(variable.referenced.get_children())[0]
            return analyze_size(node)
        else:
            for node in tu.cursor.walk_preorder():
                result = find_malloc_for_variable(node, variable)
                if result != None:
                    return result
            return None
    except:
        return None

def find_malloc_for_variable(node, variable):
    if node.kind == clang.cindex.CursorKind.BINARY_OPERATOR and node.displayname == '=':
        children = list(node.get_children())
        if len(children) == 2:
            left = children[0]  # Левая часть присваивания (переменная)
            right = children[1]  # Правая часть присваивания (вызов malloc)

            if right.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
                right = search_clang_parser_type(right)
            if left.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
                left = search_clang_parser_type(left)
            if left.kind == clang.cindex.CursorKind.DECL_REF_EXPR and left.spelling == variable.spelling:
                if right.kind == clang.cindex.CursorKind.CALL_EXPR:
                    if right.spelling == 'malloc':
                        size = list(right.get_children())[1]
                        return analyze_size(size)
                    elif right.spelling == 'calloc':
                        nmemb = list(right.get_children())[1]
                        size = list(right.get_children())[2]
                        return analyze_size(size) * analyze_size(nmemb)
    elif node.kind == clang.cindex.CursorKind.VAR_DECL and node.spelling == variable.spelling:
        for child in node.get_children():
            if child.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
                child = search_clang_parser_type(child)
            if child.kind == clang.cindex.CursorKind.CALL_EXPR:
                if child.spelling == 'malloc':
                    size = list(child.get_children())[1]
                    return analyze_size(size)
                elif child.spelling == 'calloc':
                    nmemb = list(child.get_children())[1]
                    size = list(child.get_children())[2]
                    return analyze_size(size) * analyze_size(nmemb)

def analyze_size(node):
    if node.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
        node = search_clang_parser_type(node)
    if node.kind == clang.cindex.CursorKind.INTEGER_LITERAL:
        # Если аргумент — это константа, возвращаем ее значение
        for token in list(node.get_tokens()):
            if token.kind == clang.cindex.TokenKind.LITERAL:
                try:
                    return int(token.spelling)
                except:
                    try:
                        return int(token.spelling, 16)
                    except:
                        return None
        return None
    elif node.kind == clang.cindex.CursorKind.BINARY_OPERATOR:
        # Если аргумент — это выражение, анализируем его
        left = analyze_size(list(node.get_children())[0])
        right = analyze_size(list(node.get_children())[1])

        # Выполняем операцию
        if node.displayname == '*':
            return left * right
        elif node.displayname == '/':
            return left / right
        elif node.displayname == '+':
            return left + right
        elif node.displayname == '-':
            return left - right
    elif node.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
        # Рекурсивно анализируем дочерние узлы
        for child in node.get_children():
            return analyze_size(child)
    elif node.kind == clang.cindex.CursorKind.CXX_UNARY_EXPR:
        if list(node.get_tokens())[0].spelling == 'sizeof':
            return sizes[list(node.get_tokens())[2].spelling]
    elif node.kind == clang.cindex.CursorKind.DECL_REF_EXPR:
        var_decl = node.referenced
        if var_decl and var_decl.kind == clang.cindex.CursorKind.VAR_DECL:
            # Анализируем инициализатор переменной
            for child in var_decl.get_children():
                if child.kind == clang.cindex.CursorKind.INTEGER_LITERAL:
                    for token in list(child.get_tokens()):
                        if token.kind == clang.cindex.TokenKind.LITERAL:
                            try:
                                return int(token.spelling)
                            except:
                                try:
                                    return int(token.spelling, 16)
                                except:
                                    return None
    return None



def analyze_scanf(node):
    global found_something
    format_string = list(node.get_children())[1]
    if format_string.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
        format_string = search_clang_parser_type(format_string)
    format_string = format_string.spelling

    if '%s' in format_string:
        variable = None
        if len(list(node.get_children())) == 3:
            variable = list(node.get_children())[2]
            if variable.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
                variable = search_clang_parser_type(list(node.get_children())[2])
        else:
            formats = [part for part in format_string.split() if '%' in part]
            s_index = 2
            for i in range(len(formats)):
                if '%s' in formats[i]:
                    variable = list(node.get_children())[s_index + i]
                    if variable.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
                        variable = search_clang_parser_type(variable)
                    break
        print(f'[+] Unsafe "%s" in scanf format in line {node.location.line}, target variable: {variable.spelling} (buffer overflow)')
        found_something = True
    else:
        percent_number_s_pattern = re.compile(r'%(\d+)s')
        matches = percent_number_s_pattern.findall(format_string)
        if matches:
            variable = None
            formats = [part for part in format_string.split() if '%' in part]
            s_index = 2
            for i in range(len(formats)):
                if f'%{matches[0]}s' in formats[i]:
                    variable = list(node.get_children())[s_index + i]
                    if variable.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
                        variable = search_clang_parser_type(variable)
                    break
            
            variable_size = get_variable_size(variable)

            if variable_size == None:
                return

            if variable_size != None and variable_size < int(matches[0]):
                print(f'[+] Unsafe "%{matches[0]}s" in scanf format in line {node.location.line}, '
                    + f'target variable: {variable.spelling} (buffer overflow ({int(matches[0]) - variable_size} bytes))')
                found_something = True
            
def analyze_printf(node):
    global found_something
    if len(list(node.get_children())) == 2:
        variable = list(node.get_children())[1]
        if variable.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
            variable = search_clang_parser_type(variable)
        if variable.kind == clang.cindex.CursorKind.DECL_REF_EXPR:
            try:
                variable_controlled = is_variable_controled(variable)
                if variable_controlled:
                    print(f'[+] Unsafe printf({variable.spelling}) in line {node.location.line}, target variable: {variable.spelling} (leak of data in the stack)'
                        + f'\tP.S. if you are master, you can also write into stack (check %n format)')
                    found_something = True
                else:
                    print(f'[*] Unsafe printf({variable.spelling}) in line {node.location.line}, target variable: {variable.spelling} (leak of data in the stack)'
                    + f'\tP.S. we are not sure, that `{variable.spelling}` controled by the user (if you are master, you can also write into stack (check %n format))')
                    found_something = True
            except:
                print(f'[*] Unsafe printf({variable.spelling}) in line {node.location.line}, target variable: {variable.spelling} (leak of data in the stack)'
                    + f'\tP.S. we are not sure, that `{variable.spelling}` controled by the user (if you are master, you can also write into stack (check %n format))')
                found_something = True
            
def is_variable_controled(variable):
    for node in tu.cursor.walk_preorder():
        if node.kind == clang.cindex.CursorKind.CALL_EXPR and node.spelling in read_functions:
            for child in node.get_children():
                if child.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
                    child = search_clang_parser_type(child)
                for child_of_child in child.get_children():
                    if child_of_child.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
                        child_of_child = search_clang_parser_type(child_of_child)
                    if child_of_child.spelling == variable.spelling \
                        and child_of_child.displayname == variable.displayname:
                        return True
                if child.spelling == variable.spelling \
                    and child.displayname == variable.displayname:
                    return True
    return False

def analyze_gets(node):
    if len(list(node.get_children())) == 2:
        variable = list(node.get_children())[1]
        if variable.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
            variable = search_clang_parser_type(variable)
        if variable.kind == clang.cindex.CursorKind.DECL_REF_EXPR:
            print(f'[+] Unsafe gets({variable.spelling}) in line {node.location.line}, target variable: {variable.spelling} (buffer overflow)')
            global found_something
            found_something = True

def analyze_fgets(node):
    if len(list(node.get_children())) == 4:
        variable = list(node.get_children())[1]
        if variable.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
            variable = search_clang_parser_type(variable)
        size = analyze_size(list(node.get_children())[2])
        variable_size = get_variable_size(variable)

        if size == None or variable_size == None:
            return
        
        if variable_size < size:
            print(f'[+] Unsafe `fgets` in line {node.location.line}, targer variable: {variable.spelling} (buffer overflow ({size - variable_size} bytes))')
            global found_something
            found_something = True

def analyze_read(node):
    if len(list(node.get_children())) == 4:
        variable = list(node.get_children())[2]
        if variable.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
            variable = search_clang_parser_type(variable)
        size = analyze_size(list(node.get_children())[3])
        variable_size = get_variable_size(variable)

        if size == None or variable_size == None:
            return
        
        if variable_size < size:
            print(f'[+] Unsafe `read` in line {node.location.line}, targer variable: {variable.spelling} (buffer overflow ({size - variable_size} bytes))')
            global found_something
            found_something = True

def analyze_fread(node):
    if len(list(node.get_children())) == 5:
        variable = list(node.get_children())[1]
        if variable.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
            variable = search_clang_parser_type(variable)
        size = analyze_size(list(node.get_children())[2])
        nmemb = analyze_size(list(node.get_children())[3])
        variable_size = get_variable_size(variable)

        if size == None or nmemb == None or variable_size == None:
            return
        
        if variable_size < (size * nmemb):
            print(f'[+] Unsafe `fread` in line {node.location.line}, targer variable: {variable.spelling} (buffer overflow ({(size * nmemb) - variable_size} bytes))')
            global found_something
            found_something = True
        
def analyze_strcpy(node):
    if len(list(node.get_children())) == 3:
        dst = list(node.get_children())[1]
        if dst.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
            dst = search_clang_parser_type(dst)
        src = list(node.get_children())[2]
        if src.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
            src = search_clang_parser_type(src)
        
        dst_size = get_variable_size(dst)
        src_size = get_variable_size(src)

        if dst_size == None or src_size == None:
            return
        
        if dst_size < src_size:
            print(f'[+] Unsafe `strcpy` in line {node.location.line}, targer variable: {src.spelling} (buffer overflow ({src_size - dst_size} bytes))')
            global found_something
            found_something = True

def analyze_strncpy(node):
    if len(list(node.get_children())) == 4:
        dst = list(node.get_children())[1]
        if dst.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
            dst = search_clang_parser_type(dst)
        src = list(node.get_children())[2]
        if src.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
            src = search_clang_parser_type(src)
        dsize = list(node.get_children())[3]
        if dsize.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
            dsize = search_clang_parser_type(dsize)

        dst_size = get_variable_size(dst)
        src_size = get_variable_size(src)
        dsize = analyze_size(dsize)

        if dst_size == None or src_size == None or dsize == None:
            return 

        if dsize > dst_size and dst_size < src_size:
            if src_size <= dsize:
                print(f'[+] Unsafe `strncpy` in line {node.location.line}, targer variable: {src.spelling} (buffer overflow ({src_size - dst_size} bytes))')
            else:
                print(f'[+] Unsafe `strncpy` in line {node.location.line}, targer variable: {src.spelling} (buffer overflow ({dsize - dst_size} bytes))')
            global found_something
            found_something = True

def analyze_strcat(node):
    if len(list(node.get_children())) == 3:
        dst = list(node.get_children())[1]
        if dst.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
            dst = search_clang_parser_type(dst)
        src = list(node.get_children())[2]
        if src.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
            src = search_clang_parser_type(src)
        
        dst_size = get_variable_size(dst)
        src_size = get_variable_size(src)

        if dst_size == None or src_size == None:
            return
        
        if dst_size < src_size:
            print(f'[+] Unsafe `strcat` in line {node.location.line}, targer variable: {src.spelling} (buffer overflow ({src_size - dst_size} bytes ))'
                + f'\tP.S. There could be more bytes if `dst` is not empty')
            global found_something
            found_something = True

def analyze_strncat(node):
    if len(list(node.get_children())) == 4:
        dst = list(node.get_children())[1]
        if dst.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
            dst = search_clang_parser_type(dst)
        src = list(node.get_children())[2]
        if src.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
            src = search_clang_parser_type(src)
        dsize = list(node.get_children())[3]
        if dsize.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
            dsize = search_clang_parser_type(dsize)

        dst_size = get_variable_size(dst)
        src_size = get_variable_size(src)
        dsize = analyze_size(dsize)

        if dst_size == None or src_size == None or dsize == None:
            return

        if dsize > dst_size and dst_size < src_size:
            if src_size <= dsize:
                print(f'[+] Unsafe `strncat` in line {node.location.line}, targer variable: {src.spelling} (buffer overflow ({src_size - dst_size} bytes))')
            else:
                print(f'[+] Unsafe `strncat` in line {node.location.line}, targer variable: {src.spelling} (buffer overflow ({dsize - dst_size} bytes))')
            global found_something
            found_something = True

def analyze_memcpy(node):
    if len(list(node.get_children())) == 4:
        dst = list(node.get_children())[1]
        if dst.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
            dst = search_clang_parser_type(dst)
        src = list(node.get_children())[2]
        if src.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
            src = search_clang_parser_type(src)
        dsize = list(node.get_children())[3]
        if dsize.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
            dsize = search_clang_parser_type(dsize)

        dst_size = get_variable_size(dst)
        src_size = get_variable_size(src)
        dsize = analyze_size(dsize)

        if dst_size == None or src_size == None or dsize == None:
            return

        if dsize > dst_size and dst_size < src_size:
            if src_size <= dsize:
                print(f'[+] Unsafe `memcpy` in line {node.location.line}, targer variable: {src.spelling} (buffer overflow ({src_size - dst_size} bytes))')
            else:
                print(f'[+] Unsafe `memcpy` in line {node.location.line}, targer variable: {src.spelling} (buffer overflow ({dsize - dst_size} bytes))')
            global found_something
            found_something = True

def analyze_array(node, array_node):
    global found_something
    for tmp in array_node.get_children():
        if tmp.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
            tmp = search_clang_parser_type(tmp)
        if tmp.kind == clang.cindex.CursorKind.DECL_REF_EXPR:
            variable_controlled = is_variable_controled(tmp)
            if variable_controlled and node.spelling in read_functions:
                print(f'[+] Unsafe index of `{list(array_node.get_children())[0].spelling}` in line {array_node.location.line}, target variable: {list(array_node.get_children())[1].spelling} (write-what-where)')
                found_something = True
                break
            elif variable_controlled and node.spelling in write_functions:
                print(f'[+] Unsafe index of `{list(array_node.get_children())[0].spelling}` in line {array_node.location.line}, target variable: {list(array_node.get_children())[1].spelling} (read from anywhere)')
                found_something = True
                break
            elif variable_controlled and node.spelling == 'free':
                print(f'[+] Unsafe free({list(array_node.get_children())[0].spelling}[{list(array_node.get_children())[1].spelling}]) in line {array_node.location.line}, target variable: {list(array_node.get_children())[1].spelling} (double free)')
                found_something = True
                break

def analyze_free(node):
    free_line = node.location.line
    variable = list(node.get_children())[1]
    if variable.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
        variable = search_clang_parser_type(variable)
    if variable.kind == None:
        return
    
    variable_name = ''
    if variable.kind == clang.cindex.CursorKind.UNARY_OPERATOR:
        variable_name = list(variable.get_children())[0].spelling
    elif variable.kind == clang.cindex.CursorKind.ARRAY_SUBSCRIPT_EXPR:
        variable_name = f'{list(variable.get_children())[0].spelling}[{list(variable.get_children())[1].spelling}]'
    else:
        variable_name = variable.spelling
    
    found = False
    for node in tu.cursor.walk_preorder():
        if found:
            break

        if node.location.line > free_line:
            try:
                if node.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
                    node = search_clang_parser_type(node)

                if node.kind == clang.cindex.CursorKind.VAR_DECL:
                    continue

                for child in node.get_children():
                    if child.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
                        child = search_clang_parser_type(child)
                    child_name = child.spelling
                    if child.kind == clang.cindex.CursorKind.ARRAY_SUBSCRIPT_EXPR:
                        child_name = f'{list(child.get_children())[0].spelling}[{list(child.get_children())[1].spelling}]'
                    if child_name == variable_name:
                        if child.kind == clang.cindex.CursorKind.VAR_DECL:
                            return
                        print(f'[+] Use after free in line {node.location.line}, target  variable: {variable_name}')
                        found = True
                        global found_something
                        found_something = True
                        break
            except:
                continue
                

def analyze_code(file_path):
    index = clang.cindex.Index.create()
    global tu
    tu = index.parse(file_path, args=['-std=c11'])
    for node in tu.cursor.walk_preorder():
        try:
            if node.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
                node = search_clang_parser_type(node)

            for tmp in node.get_children():
                if tmp.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
                    tmp = search_clang_parser_type(tmp)
                if tmp.kind == clang.cindex.CursorKind.ARRAY_SUBSCRIPT_EXPR and node.kind == clang.cindex.CursorKind.CALL_EXPR:
                    analyze_array(node, tmp)
                    break

            if node.kind == clang.cindex.CursorKind.CALL_EXPR:
                match node.spelling:
                    case 'scanf':
                        analyze_scanf(node)
                    case '__isoc99_scanf':
                        analyze_scanf(node)
                    case 'printf':
                        analyze_printf(node)
                    case 'gets':
                        analyze_gets(node)
                    case 'fgets':
                        analyze_fgets(node)
                    case 'read':
                        analyze_read(node)
                    case 'fread':
                        analyze_fread(node)
                    case 'strcpy':
                        analyze_strcpy(node)
                    case 'strncpy':
                        analyze_strncpy(node)
                    case 'strcat':
                        analyze_strcat(node)
                    case 'strncat':
                        analyze_strncat(node)
                    case 'memcpy':
                        analyze_memcpy(node)
                    case 'free':
                        analyze_free(node)
        except:
            continue
    if not found_something:
        print('Nothing found :(')


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Использование: ./analyzer.py <файл.c>")
    else:
        analyze_code(sys.argv[1])