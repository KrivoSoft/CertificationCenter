#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  work_with_certs.py
#
#  Copyright 2019 Marka <marka@evil>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#
from datetime import datetime
from pathlib import Path
from OpenSSL import crypto
import os
import pexpect
import yaml
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired


def search_for_certificates(path_to_folder):
    """Поиск всех сертификатов в директории."""
    p = Path(path_to_folder).glob('*.crt')
    files = [x for x in p if x.is_file()]
    return files


def info_about_cert(certificate):
    """Извлечение информации о сертификате."""
    our_cert = open(str(certificate)).read()
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, our_cert)
    time_start = cert.get_notBefore()
    time_start = str(time_start, 'utf-8')
    time_start = datetime.strptime(time_start, "%Y%m%d%H%M%SZ")
    time_end = cert.get_notAfter()
    time_end = str(time_end, 'utf-8')
    time_end = datetime.strptime(time_end, "%Y%m%d%H%M%SZ")
    data_list = {
            'name': certificate.stem,
            'country': cert.get_subject().C,
            'oblast': cert.get_subject().ST,
            'city': cert.get_subject().L,
            'company': cert.get_subject().O,
            'unit': cert.get_subject().OU,
            'common_name': cert.get_subject().CN,
            'issuer': cert.get_issuer().CN,
            'email': cert.get_subject().emailAddress,
            'time_start': time_start,
            'time_end': time_end
    }

    return data_list


def load_certs():
    '''Загружает сертификаты в директории'''
    all_cert = []

    # Загружаем пути из конфигурационного файла
    with open('config.yaml') as info:
        config_dict = yaml.safe_load(info)
    path_to_public_cert = config_dict.get('path_to_public_cert')
    path_to_trusted_cert = config_dict.get('path_to_trusted_cert')

    certs_in_directory = search_for_certificates(path_to_public_cert)
    for one_cert in certs_in_directory:
        dict_with_info = info_about_cert(one_cert)
        if Certificate.signed_by_ca(one_cert, path_to_trusted_cert) is True:
            if Certificate.is_in_crl(one_cert) is False:
                all_cert.append(Certificate(dict_with_info))
    return all_cert


class Certificate():
    def __init__(self, data_list):
        """Создание нового сертифката."""
        cert_name = data_list.get('name')
        country = data_list.get('country')
        oblast = data_list.get('oblast')
        city = data_list.get('city')
        company = data_list.get('company')
        unit = data_list.get('unit')
        common_name = data_list.get('common_name')
        issuer = data_list.get('issuer')
        email = data_list.get('email')
        time_start = data_list.get('time_start')
        time_end = data_list.get('time_end')

        to_time = datetime.strptime
        if type(time_start) is str:
            self.time_start = to_time(time_start, "%d-%m-%Y-%H-%M")
        else:
            self.time_start = time_start
        if type(time_end) is str:
            self.time_end = to_time(time_end, "%d-%m-%Y-%H-%M")
        else:
            self.time_end = time_end
        self.cert_name = cert_name
        self.common_name = common_name
        self.issuer = issuer
        self.country = country
        self.oblast = oblast
        self.city = city
        self.company = company
        self.unit = unit
        self.email = email

    def is_valid(cert):
        """Проверка срока действия сертификата."""
        now = datetime.now()
        if (cert.time_end >= now) & (cert.time_start <= now):
            return True
        else:
            return False

    def revoke_certificate(client_name):
        """Отзыв сертфииката с помощью easy-rsa"""
        os.chdir('easy-rsa')

        child = pexpect.spawn('bash')

        command_to_run = "source vars"
        child.sendline(command_to_run)

        command_to_run = " ".join(['./revoke-full', client_name])
        child.sendline(command_to_run)

        child.sendline('ls')
        child.close()

        os.chdir(path_to_project)

    def signed_by_ca(doubtful_cert, trusted_cert):
        '''Подтверждение сертификата'''
        # Загружаем доверенный и проверяемый сертификаты
        doubtful_cert = open(str(doubtful_cert)).read()
        open_cert = crypto.load_certificate
        doubtful_cert = open_cert(crypto.FILETYPE_PEM, doubtful_cert)
        open_key = open(trusted_cert).read()
        trusted_cert = Path(trusted_cert)
        trusted_cert = open_cert(crypto.FILETYPE_PEM, open_key)

        store = crypto.X509Store()
        store.add_cert(trusted_cert)
        store_ctx = crypto.X509StoreContext(store, doubtful_cert)
        try:
            store_ctx.verify_certificate()
            return True
        except crypto.X509StoreContextError:
            return False

    def is_in_crl(doubtful_cert):
        '''Проверка есть ли сертификат в CRL-файле'''
        # Загружаем путь из конфигурационного файла
        with open('config.yaml') as info:
            config_dict = yaml.safe_load(info)
        path_to_crl = config_dict.get('path_to_crl')

        # Загружаем CRL-файл
        open_crl = open(path_to_crl).read()
        crl_pem = crypto.load_crl(crypto.FILETYPE_PEM, open_crl)

        # Загружаем сертификат
        doubtful_cert = open(str(doubtful_cert)).read()
        open_cert = crypto.load_certificate
        doubtful_cert = open_cert(crypto.FILETYPE_PEM, doubtful_cert)
        serial_number = doubtful_cert.get_serial_number()

        list_revoked_certs = []
        revoked_certs = crl_pem.get_revoked()

        # Сохраняем все серийные номера в массив
        for serial_num in revoked_certs:
            decoded_number = int(serial_num.get_serial(), 16)
            list_revoked_certs.append(decoded_number)

        if serial_number in list_revoked_certs:
            return True
        else:
            return False

    def create_cert(data_list):
        """Создание ключа, запроса на сертификат и сертификата клиента"""
        country = data_list.get('country')
        oblast = data_list.get('oblast')
        city = data_list.get('city')
        company = data_list.get('company')
        unit = data_list.get('unit')
        common_name = data_list.get('common_name')
        name = data_list.get('name')
        email = data_list.get('email')

        os.chdir('easy-rsa/')

        command = "bash"
        child = pexpect.spawn(command)

        command_to_run = "source vars"
        child.sendline(command_to_run)

        command_to_run = " ".join(['./build-key', name])
        child.sendline(command_to_run)

        string_to_expect = ".*?"
        child.expect(string_to_expect)
        child.sendline(country)

        child.expect(string_to_expect)
        child.sendline(oblast)

        child.expect(string_to_expect)
        child.sendline(city)

        child.expect(string_to_expect)
        child.sendline(company)

        child.expect(string_to_expect)
        child.sendline(unit)

        child.expect(string_to_expect)
        child.sendline(common_name)

        child.expect(string_to_expect)
        child.sendline(name)

        child.expect(string_to_expect)
        child.sendline(email)

        child.expect(string_to_expect)
        child.sendcontrol('m')

        child.expect(string_to_expect)
        child.sendcontrol('m')

        child.expect(string_to_expect)
        child.sendline('y')

        child.expect(string_to_expect)
        child.sendline('y')

        child.expect(string_to_expect)
        child.sendline('ls')

        child.close()
        os.chdir(path_to_project)


class CreateForm(FlaskForm):
    '''Форма ввода информации для создания сертификата'''
    country = StringField('Код страны', validators=[DataRequired()])
    oblast = StringField('Область/регион', validators=[DataRequired()])
    city = StringField('Город', validators=[DataRequired()])
    company = StringField('Компания', validators=[DataRequired()])
    unit = StringField('Отдел', validators=[DataRequired()])
    common_name = StringField('Common Name', validators=[DataRequired()])
    name = StringField('Имя', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])


class RevokeForm(FlaskForm):
    '''Форма ввода информации для отзыва сертификата'''
    name = StringField('Имя сертификата ', validators=[DataRequired()])


path_to_project = os.path.abspath(os.curdir)
