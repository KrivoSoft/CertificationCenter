#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  routes.py
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
from flask import render_template
from app import app

# Привязка функции к URL-адресу
@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html', title='Home', all_cert = all_cert)
    
    
@app.route('/all_certificates')
def all_certificates():
    return render_template('all_certificates.html', title='all_certificates', all_cert = all_cert)


class Certificate():
	# Создание нового сертифката и добавление его в список всех сертификатов
	def __init__(self, time_start, time_end, subject, issuer):
		self.time_start = datetime.strptime(time_start, "%d-%m-%Y")
		self.time_end = datetime.strptime(time_end, "%d-%m-%Y")
		self.subject = subject
		self.issuer = issuer
		all_cert.append(self)
	
	
	# Проверка на валидность сертификата
	def IsValid(cert):
		now = datetime.now()
		if (cert.time_end >= now) & (cert.time_start <= now):
			return True
		else:
			return False
	
	
all_cert = []
Certificate('01-01-1990', '01-01-2010', 'personal-site.com', 'CertCenter')
Certificate('01-09-2019', '01-01-2020', 'big-company.com', 'CertCenter')
Certificate('01-01-2018', '01-09-2019', 'my-site.com', 'CertCenter')
print (Certificate.IsValid(all_cert[0])) # False
print (Certificate.IsValid(all_cert[1])) # False
print (Certificate.IsValid(all_cert[2])) # True

