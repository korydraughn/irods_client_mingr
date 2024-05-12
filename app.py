from flask import Flask, render_template, request, abort, session, redirect, url_for, g

import datetime
import json
import requests
import os

app = Flask(__name__)

# TODO Required for session support. Use python secrets module. Flask has more docs about this too.
app.secret_key = 'THIS NEEDS TO BE GENERATED ON STARTUP'

IRODS_HTTP_API_URL = 'http://localhost:9000/irods-http-api/0.3.0'
IRODS_ZONE_NAME = 'tempZone'

@app.route('/')
def index():
    # Already logged in.
    if 'username' in session:
        return redirect(url_for('filesystem', collection=f'/{IRODS_ZONE_NAME}/home/{session["username"]}'))

    return render_template('index.html', title='Welcome')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Already logged in.
    if 'username' in session:
        return redirect(url_for('filesystem', collection=f'/{IRODS_ZONE_NAME}/home/{session["username"]}'))

    if request.method == 'GET':
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        app.logger.debug(f'Authenticating user [{username}]')
        r = requests.post(IRODS_HTTP_API_URL + '/authenticate', auth=(username, request.form['password']))

        if r.status_code != 200:
            app.logger.error('Invalid username and/or password.')
            abort(401) # TODO Use a dedicated page and error handler.

        app.logger.debug('Authentication was successful.')

        # Start a new session for the user and redirect them to the filesystem page.
        session.clear()
        session['username'] = username
        session['fq_username'] = f'{username}#{IRODS_ZONE_NAME}'
        session['bearer_token'] = r.text
        return redirect(url_for('filesystem', collection=f'/{IRODS_ZONE_NAME}/home/{username}'))

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/filesystem')
def filesystem():
    if 'username' not in session:
        app.logger.error('User not authenticated. Access to filesystem view denied.')
        abort(401)

    collection = request.args.get('collection')
    app.logger.debug(f'collection = [{collection}]')

    if not collection:
        app.logger.debug('[collection] not specified. Defaulting to home collection.')
        coll_path = f'/{IRODS_ZONE_NAME}/home/{session["username"]}'
    else:
        coll_path = os.path.normpath(collection)

    # Get list of collections under the collection.
    r = requests.get(IRODS_HTTP_API_URL + '/query', headers={'Authorization': f'Bearer {session["bearer_token"]}'}, params={
        'op': 'execute_genquery',
        'query': f"select COLL_ID, COLL_NAME where COLL_PARENT_NAME = '{coll_path}'",
        'count': 20
    })

    if r.status_code != 200:
        app.logger.error('Error retrieving collection listing for user.')
        abort(500)

    r_json = r.json()
    if r_json['irods_response']['status_code'] < 0:
        app.logger.error('Error retrieving collection listing for user.')
        abort(500)

    collections = r_json['rows']

    # Get list of data objects under the collection.
    r = requests.get(IRODS_HTTP_API_URL + '/query', headers={'Authorization': f'Bearer {session["bearer_token"]}'}, params={
        'op': 'execute_genquery',
        'query': f"select DATA_ID, COLL_NAME, DATA_NAME, DATA_SIZE where COLL_NAME = '{coll_path}'",
        'count': 20
    })

    if r.status_code != 200:
        app.logger.error('Error retrieving data object listing for user.')
        abort(500)

    r_json = r.json()
    if r_json['irods_response']['status_code'] < 0:
        app.logger.error('Error retrieving data object listing for user.')
        abort(500)

    return render_template(
        'filesystem.html',
        title='Filesystem',
        current_collection=coll_path,
        collections=collections,
        data_objects=r_json['rows']
    )

@app.route('/data-object-info')
def data_object_info():
    data_id = request.args['data_id']
    app.logger.debug(f'data_id = [{data_id}]')

    r = requests.get(IRODS_HTTP_API_URL + '/query', headers={'Authorization': f'Bearer {session["bearer_token"]}'}, params={
        'op': 'execute_genquery',
        'query': "select COLL_NAME, DATA_NAME, DATA_REPL_NUM, DATA_REPL_STATUS, DATA_SIZE, "
                 f"DATA_PATH, DATA_CHECKSUM, RESC_NAME, DATA_CREATE_TIME, DATA_MODIFY_TIME where DATA_ID = '{data_id}'",
        'count': 20
    })

    if r.status_code != 200:
        app.logger.error('Error retrieving data object information.')
        abort(500)

    r_json = r.json()
    if r_json['irods_response']['status_code'] < 0:
        app.logger.error('Error retrieving data object information.')
        abort(500)

    replicas = r_json['rows']
    logical_path = replicas[0][0] + '/' + replicas[0][1]
    app.logger.debug(f'logical_path = [{logical_path}]')

    # Update the timestamps to be in ISO8601 format.
    # The conversion to an integer ignores leading zeros. 
    for r in replicas:
        r[8] = datetime.datetime.utcfromtimestamp(int(r[8]))
        r[9] = datetime.datetime.utcfromtimestamp(int(r[9]))

    r = requests.get(IRODS_HTTP_API_URL + '/data-objects', headers={'Authorization': f'Bearer {session["bearer_token"]}'}, params={
        'op': 'stat',
        'lpath': logical_path
    })

    if r.status_code != 200:
        app.logger.error('Error retrieving permissions for data object.')
        abort(500)

    r_json = r.json()
    if r_json['irods_response']['status_code'] < 0:
        app.logger.error(r_json['irods_response']['status_message'])
        abort(500)

    return render_template(
        'data_object_info.html',
        title='Data Object Information',
        logical_path=logical_path,
        data_id=data_id,
        replicas=replicas,
        permissions=r_json['permissions']
    )

@app.get('/query')
def query():
    query_string = request.args.get('query_string')

    if not query_string:
        return render_template('query.html', title='Query')

    app.logger.debug(f'query_string = [{query_string}]')

    r = requests.get(IRODS_HTTP_API_URL + '/query', headers={'Authorization': f'Bearer {session["bearer_token"]}'}, params={
        'op': 'execute_genquery',
        'query': query_string,
        'count': 20
    })

    if r.status_code != 200:
        app.logger.error('Error executing GenQuery1 string.')
        abort(500)

    r_json = r.json()
    if r_json['irods_response']['status_code'] < 0:
        app.logger.error('Error executing GenQuery1 string.')
        abort(500)

    app.logger.debug('results = ' + json.dumps(r_json['rows']))
    return r_json['rows']

@app.get('/rule-execution')
def rule_execution():
    rule_code = request.args.get('rule_code')

    if not rule_code:
        r = requests.get(IRODS_HTTP_API_URL + '/rules', headers={'Authorization': f'Bearer {session["bearer_token"]}'}, params={
            'op': 'list_rule_engines'
        })

        if r.status_code != 200:
            app.logger.error('Error retrieving list of available rule engine plugins.')
            abort(500)

        r_json = r.json()
        if r_json['irods_response']['status_code'] < 0:
            app.logger.error('Error retrieving list of available rule engine plugins.')
            abort(500)

        return render_template('rule_execution.html',
            title='Rule Execution',
            plugin_instances=r_json['rule_engine_plugin_instances']
        )

    app.logger.debug(f'rule_code = [{rule_code}]')

    data = {'op': 'execute', 'rule-text': rule_code}
    plugin_instance = request.args.get('plugin_instance')
    if plugin_instance:
        data['rep-instance'] = plugin_instance
    app.logger.debug(f'plugin_instance = [{plugin_instance}]')
    r = requests.post(IRODS_HTTP_API_URL + '/rules', headers={'Authorization': f'Bearer {session["bearer_token"]}'}, data=data)

    if r.status_code != 200:
        app.logger.error('Error executing rule code.')
        abort(500)

    r_json = r.json()
    if r_json['irods_response']['status_code'] < 0:
        app.logger.error('Error executing rule code.')
        abort(500)

    r_json.pop('irods_response')
    return r_json
