import os
import sys
import json
import re

directory_file = sys.argv[1]
docs_path = sys.argv[2]
success = True


def check_md_content(md_file):
    global success

    if not os.path.exists(md_file):
        print(f'{md_file} not exists')
        success = False
        return

    md_content = re.sub(r'<!--([\s\S]*?)-->', '', open(md_file, 'r').read())

    if 'ee' in directory_file:
        md_content = re.sub(r'{% emqxce %}([\s\S]*?){% endemqxce %}', '', md_content)
    else:
        md_content = re.sub(r'{% emqxee %}([\s\S]*?){% endemqxee %}', '', md_content)

    image_list = re.findall('(.*?)!\[(.*?)\]\((.*?)\)', md_content)
    url_list = re.findall('(.*?)\[(.*?)\]\((.*?)\)', md_content)
    for url in url_list:
        if url[0].endswith('!'):
            continue
        if url[2].startswith(('http://', 'https://', '<', '#', 'mailto:', 'tel:')):
            continue
        url_path = url[2].split('.md')[0]
        ref_md_path = os.path.join(f'{"/".join(md_file.split("/")[:-1])}/', f'{url_path}.md')

        if not os.path.exists(ref_md_path):
            print(f'In {md_file}：', end='')
            print(f'{url[2]} not found or not in {directory_file}')
            success = False

    for image in image_list:
        if image[0].startswith('<!--'):
            continue
        if image[2].startswith(('http://', 'https://', '<')):
            continue
        image_path = os.path.join(f'{"/".join(md_file.split("/")[:-1])}/', image[2])

        if not os.path.exists(image_path):
            print(f'In {md_file}：', end='')
            print(image[2], 'does not exist')
            success = False


def get_md_files(dir_config, path):
    global success
    md_list = []
    for i in dir_config:
        md_name = i.get('path')
        md_children = i.get('children')

        if md_name:
            if md_name.startswith(('http://', 'https://')):
                continue
            elif md_name == './':
                md_list.append(f'{docs_path}/{path}/README.md')
            else:
                md_list.append(f'{docs_path}/{path}/{md_name}.md')

        if md_children:
            md_list += get_md_files(md_children, path)

    return list(set(md_list))


if __name__ == '__main__':
    if os.path.exists(f'{docs_path}/{directory_file}'):
        md_file_list = []
        config_dict = json.load(open(f'{docs_path}/{directory_file}'))
        md_file_list += get_md_files(config_dict['cn'], 'zh_CN')
        md_file_list += get_md_files(config_dict['en'], 'en_US')

        for file_path, dir_list, file_list in os.walk(docs_path):
            for file_name in file_list:
                if file_name.split('.')[-1] != 'md':
                    continue
                md_path = os.path.join(file_path, file_name)
                if md_path not in md_file_list:
                    os.remove(md_path)

        for file in md_file_list:
            check_md_content(file)

    if not success:
        sys.exit('No pass!')
    else:
        print('Check completed!')
