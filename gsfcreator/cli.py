#!/usr/bin/python

import click
import os
import json
import configparser
import gsfcreator.config as device_config
HOME = os.path.expanduser("~")
CONF_FILE = HOME + "/.gsfcreator.json"

@click.group()
def cli():
    pass


@cli.command("generate", help="Generate device gsfIds")
def generate_gsf_ids():
    """Generate gsf ids"""
    config_files = get_deivce_config_tree()
    config_dir = get_device_config_dir()
    config = configparser.ConfigParser()
    config.read(get_gsfid_dir())
    for section in config_files:
        for config_file in config_files[section]:
            if isinstance(config_file, str):
                if section != "other":
                    config_file = section + "/" + config_file
                device_config.readConfig(config_dir + "/" + config_file)




@cli.command(help="Initialize the cli; Need to do on first run.")
def init():
    """Initialize the generator"""
    directory = os.path.expanduser(input("Enter device configs directory: "))
    gsfid_file = os.path.expanduser(input("Enter gsfid output file: "))
    # check if config dir exists, create it otherwise
    if not os.path.isdir(directory):
        os.mkdir(directory)

    if not os.path.exists(CONF_FILE) or (os.path.exists(CONF_FILE) and click.confirm('An existing config file already exists, do you want to overwrite it?')):
        with open(CONF_FILE, 'w+') as conf_file:
            # @todo more configurations?
            conf = {
                'device_config_directory': directory,
                'gsfid_output_file': gsfid_file
            }

            json.dump(conf, conf_file)


@cli.command("list", help="List gsf ids")
def list_ids():
    """List existing gsf ids"""
    pass


def get_device_config_dir():
    with open(CONF_FILE, 'r') as conf_file:
        conf = json.load(conf_file)

    return conf['device_config_directory']


def get_gsfid_dir():
    with open(CONF_FILE, 'r') as conf_file:
        conf = json.load(conf_file)

    return conf['gsfid_output_file']


def get_deivce_config_tree():
    config_store = get_device_config_dir()
    config_dir_structure = {}
    dir_tree(config_dir_structure, config_store, 'other')
    click.echo(config_dir_structure)
    return config_dir_structure


def dir_tree(dir_dict, root, section):
    dir_dict[section] = []
    for item in os.listdir(root):
        if os.path.isdir(root + '/' + item):
            if section == 'other':
                dir_tree(dir_dict, root + '/' + item, item)
            elif type(dir_dict[section]) is list:
                dir_dict[section].append({})
                dir_tree(dir_dict[section][-1], root + '/' + item, section + '/' + item)
            else:
                dir_tree(dir_dict[section], root + '/' + item, section + '/' + item)
        else:
            dir_dict[section].append(item)



