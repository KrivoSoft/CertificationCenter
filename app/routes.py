#!/usr/bin/env python3
# pycryptodome 3.4.3
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

from flask import render_template, request
from app import app
from app import work_with_certs
import os
from werkzeug.datastructures import MultiDict
from flask_wtf import FlaskForm

@app.route('/')
@app.route('/index')
def index():
    """Привязка функции к URL-адресу."""
    return render_template('index.html', title='Home')


@app.route('/all_certificates', methods=('GET', 'POST'))
def all_certificates():
    if request.method == 'POST':
        return revoke(request.form['rev_this'])
    """Привязка функции к URL-адресу."""
    certs = work_with_certs.load_certs()
    return render_template('all_certificates.html', title='All', all_cert=certs)


@app.route('/create_certificate', methods=('GET', 'POST'))
def create_certificate():
    form = work_with_certs.CreateForm()
    if request.method == 'POST' and form.validate():
        data_list = {
            'country': request.form['country'],
            'oblast': request.form['oblast'],
            'city': request.form['city'],
            'company': request.form['company'],
            'unit': request.form['unit'],
            'common_name': request.form['common_name'],
            'name': request.form['name'],
            'email': request.form['email']
        }
        work_with_certs.Certificate.create_cert(data_list)
        certs = work_with_certs.load_certs()
        return render_template('all_certificates.html', title='All', all_cert=certs)
    return render_template('create_certificate.html', title='Create', form=form)


@app.route('/revoke', methods=('GET', 'POST'))
def revoke(revoke_this=None):
    form = work_with_certs.RevokeForm()
    if revoke_this is not None:
        form = work_with_certs.RevokeForm(formdata=MultiDict({'name': revoke_this}))
    if request.method == 'POST' and form.validate():
        cert_name = form.name.data
        work_with_certs.Certificate.revoke_certificate(cert_name)
        certs = work_with_certs.load_certs()
        return render_template('all_certificates.html', title='All', all_cert=certs)
    return render_template('revoke.html', title='Revoke', form=form)


SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY
