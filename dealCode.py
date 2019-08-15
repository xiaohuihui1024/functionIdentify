# -*- coding: utf-8 -*-
import os
import re
import chardet
import sys
import clang.cindex as cc

# 解析文件名的正则表达式
pattern_filename = re.compile('(CVE.*?)_(.*)_([0-9a-f]*)_([0-9\-]*?)_(.*)\.(.*)')

def readFile(file_path):
    """
    自动识别文件编码，并根据该编码打开文件
    :return: 文件指针
    """
    with open(file_path, 'rb') as f:
        # 当前文件编码
        cur_encoding = chardet.detect(f.read())['encoding']
        f.close()
    # 用获取的编码读取该文件而不是python3默认的utf-8读取。
    return open(file_path, encoding=cur_encoding)

def parse_function_lines(filepath):
    """
    by given code filepath, parse its all funtion_lines
    :param filepath: 
    :return: function_msg list
    """
    index = cc.Index.create()
    tu = index.parse(filepath, args=[])
    ast = tu.cursor
    results = list()
    for node in ast.walk_preorder():
        # node.is_definition and node.location.file can filter the system lib function
        if node.is_definition() and str(node.location.file) == str(tu.cursor.spelling) and str(node.kind).split('.')[1] in ["CXX_METHOD", "FUNCTION_DECL", "DESTRUCTOR", "CONSTRUCTOR"]:
            # this node is the function node
            results.append({
                'functionName': node.spelling,
                'startLine': node.extent.start.line,
                'endLine': node.extent.end.line,
                'functionType': str(node.kind).split('.')[1]
            })
    return results

def parse_filename(filename):
    """
    正则解析文件名，提取各个部分的内容
    """
    matchResult = re.match(pattern_filename, filename)
    if matchResult:
        return {
            'cve_id': matchResult.group(1),
            'git_name': matchResult.group(2),
            'hash': matchResult.group(3),
            'lines': matchResult.group(4),
            'filename': matchResult.group(5),
            'extension': matchResult.group(6)
        }
    else:
        return None

def get_include_lines(codes):
    """
    提取代码中include的行
    :param codes: 传入将代码 readlines 的结果
    :return: 代码中 # 开头的代码
    """
    results = list()
    # 多行标志
    flag = None
    for line in codes:
        clean_line = line.strip()
        if clean_line.startswith("#") or flag:
            results.append(line)
            flag = False
        if clean_line.endswith("\\"):
            flag = True
    return results
    pass

def is_target(filename):
    pass

def DealCode(filepath, dst_path):
    # 解析出文件名
    path, filename = os.path.split(filepath)
    FileInfo = parse_filename(filename)

    if FileInfo:
        if FileInfo['extension'] in ['c', 'cpp', 'h']:
            # 解析所有函数位置
            allLoctionInfo = parse_function_lines(filepath)
            # 不能放到后边，路径问题
            f = readFile(filepath)
            # 将处理结果存到dst_path下，首先创建相关的文件夹
            if not os.path.exists(dst_path):
                os.mkdir(dst_path)
            os.chdir(dst_path)
            # 创建第一级目录
            if not os.path.exists(FileInfo['cve_id']):
                os.mkdir(FileInfo['cve_id'])
            os.chdir(FileInfo['cve_id'])
            # 创建第二级目录
            if not os.path.exists(FileInfo['git_name'] + '-' +FileInfo['hash']):
                os.mkdir(FileInfo['git_name'] + '-' + FileInfo['hash'])
            os.chdir(FileInfo['git_name'] + '-' + FileInfo['hash'])


            # 首先存一份原始文件，编码为utf-8
            with open(filename, 'w+', encoding='utf-8') as nf:
                nf.write(f.read())
                nf.close()
            # 之前read过了，需要将指针回退到起始位置
            f.seek(0)

            # 目录初始化完毕，开始处理数据
            # 读取代码文件，把每一行存到list中
            codes = f.readlines()
            print('start dealing... ', filename)


            # 提取出 include和 define
            include_lines = get_include_lines(codes)

            # 根据文件名中的 行数 依次查找
            target_lines = FileInfo['lines'].split('-')
            for target_line in target_lines:
                # TODO：根据patch内容判断是否添加，后期加入
                # 每次查找都从头到尾遍历一遍
                flag = False # 默认为没找到
                for loctionInfo in allLoctionInfo:
                    try:
                        # TODO:如果可以确保dict中数据为int，可以去掉
                        startLine = int(loctionInfo['startLine'])
                        endLine = int(loctionInfo['endLine'])
                        t_line = int(target_line) + 3
                        if startLine <= t_line <= endLine:
                            # 找到了
                            flag = True
                            with open('%s_%s_%s.%s'%(target_line, loctionInfo['functionName'], FileInfo['filename'], FileInfo['extension']),'w+',encoding='utf-8') as tf:
                                # 写入include，define
                                for include_line in include_lines:
                                    tf.write(include_line)
                                # 写入相关代码
                                for i in range(startLine, endLine+1):
                                    tf.write(codes[i-1])
                                tf.close()
                    except IndexError as ie:
                        print('IndexError：', ie)
                    except Exception as e:
                        with open('../../errorMsg.txt','a+',encoding='utf-8') as ef:
                            ef.write('FileName: %s\nLine:%d\n'%(filename,loctionInfo['startLine']))
                            ef.write(str(e))
                            ef.write('\n\n')
                            ef.close()
                        print('FileName: %s\nLine:%d\n\n'%(filename,loctionInfo['startLine']))
                        print(e)
                if not flag:
                    # 没找到
                    with open('%s_%s_%s.%s' % (
                    target_line, 'notfun', FileInfo['filename'], FileInfo['extension']), 'a+',
                              encoding='utf-8') as tf:
                        tf.close()
            f.close()
            # 必须！回退！
            os.chdir('../../../')
        else:
            print('不支持 %s 文件拓展名' % FileInfo['extension'])
    else:
        print('文件名格式有误 %s' % filename)

# 返回dir目录下的所有 指定格式的文件
def getallfilesofwalk(dir, extension_list):
    if not os.path.isdir(dir):
        print('%s is not dir' % dir)
        return
    dirlist = os.walk(dir)
    for root, dirs, files in dirlist:
        for file in files:
            if os.path.splitext(file)[1] in extension_list:
                yield os.path.join(root, file)

'''
{'', '.idx', '.sample', '.am', '.cxx', '.pl', '.h', '.sh', '.gitignore', 
'.t', '.inc', '.cc', '.gitattributes', '.md', '.cpp', '.txt', '.pod', 
'.ac', '.c', '.xml', '.adoc', '.pack', '.py', '.js', '.in', '.out'}
'''

def getallextensions(dir):
    results = set()
    if not os.path.isdir(dir):
        print('%s is not dir' % dir)
        return
    dirlist = os.walk(dir)
    for root, dirs, files in dirlist:
        for file in files:
            if os.path.splitext(file)[1] in ['.idx', '.sample', '.am', '.pl', '.sh',
'.t', '.inc', '.gitattributes', '.md', '.pod',
'.ac', '.xml', '.adoc', '.pack', '.py', '.js', '.in', '.out']:
                print(os.path.join(root, file))
            results.add(os.path.splitext(file)[1])
    return results
# 测试，输入 代码文件路径
def test(file_dir, dst_dir):
    # file_dir = file_dir if file_dir.endswith('/') else file_dir + '/'
    for root, dirs, files in os.walk(file_dir):
        for file in files:
            DealCode(file_dir+file, dst_dir)


if __name__ == '__main__':
    CodePath = ".//Project//VulDetect//cwe119_old_file//cwe-119"
    dealedPath = "./dealedcwe-119"
    for filepath in getallfilesofwalk(sys.argv[1], ['.cpp', '.c', '.h', '.cc', '.cxx']):
        DealCode(filepath, sys.argv[2])
    # print(parse_function_lines('./testcppCode/People1.cpp'))
    # test(CodePath, dealedPath)