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

    # Get total number of collections under the collection.
    r = requests.get(IRODS_HTTP_API_URL + '/query', headers={'Authorization': f'Bearer {session["bearer_token"]}'}, params={
        'op': 'execute_genquery',
        'query': f"select count(COLL_ID) where COLL_PARENT_NAME = '{coll_path}'"
    })

    if r.status_code != 200:
        app.logger.error('Error retrieving collection listing for user.')
        abort(500)

    r_json = r.json()
    if r_json['irods_response']['status_code'] < 0:
        app.logger.error('Error retrieving collection listing for user.')
        abort(500)

    total_collections = r_json['rows'][0][0]

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

    # Get total number of data objects under the collection.
    r = requests.get(IRODS_HTTP_API_URL + '/query', headers={'Authorization': f'Bearer {session["bearer_token"]}'}, params={
        'op': 'execute_genquery',
        'query': f"select count(DATA_ID) where COLL_NAME = '{coll_path}'",
    })

    if r.status_code != 200:
        app.logger.error('Error retrieving data object listing for user.')
        abort(500)

    r_json = r.json()
    if r_json['irods_response']['status_code'] < 0:
        app.logger.error('Error retrieving data object listing for user.')
        abort(500)

    total_data_objects = r_json['rows'][0][0]

    # Get list of data objects under the collection.
    r = requests.get(IRODS_HTTP_API_URL + '/query', headers={'Authorization': f'Bearer {session["bearer_token"]}'}, params={
        'op': 'execute_genquery',
        'query': f"select DATA_ID, COLL_NAME, DATA_NAME where COLL_NAME = '{coll_path}'",
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
        total_data_objects=total_data_objects,
        data_objects=r_json['rows'],
        total_collections=total_collections,
        collections=collections,
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

    for r in replicas:
        # Update the timestamps to be in ISO8601 format. The conversion to an
        # integer ignores leading zeros. 
        r[8] = datetime.datetime.utcfromtimestamp(int(r[8]))
        r[9] = datetime.datetime.utcfromtimestamp(int(r[9]))

        # Convert replica status integer to its symbolic name for readability.
        sym_name_idx = int(r[3])
        r[3] = ['stale', 'good', 'intermediate', 'read-locked', 'write-locked'][sym_name_idx]

    r = requests.get(IRODS_HTTP_API_URL + '/query', headers={'Authorization': f'Bearer {session["bearer_token"]}'}, params={
        'op': 'execute_genquery',
        'query': 'select META_DATA_ATTR_NAME, META_DATA_ATTR_VALUE, META_DATA_ATTR_UNITS '
                 f"where COLL_NAME = '{replicas[0][0]}' and DATA_NAME ='{replicas[0][1]}'",
        'count': 250
    })

    if r.status_code != 200:
        app.logger.error('Error retrieving metadata for data object.')
        abort(500)

    r_json = r.json()
    if r_json['irods_response']['status_code'] < 0:
        app.logger.error(r_json['irods_response']['status_message'])
        abort(500)

    metadata = r_json['rows']

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
        metadata=metadata,
        permissions=r_json['permissions']
    )

@app.route('/collection-info')
def collection_info():
    coll_id = request.args['coll_id']
    app.logger.debug(f'coll_id = [{coll_id}]')

    r = requests.get(IRODS_HTTP_API_URL + '/query', headers={'Authorization': f'Bearer {session["bearer_token"]}'}, params={
        'op': 'execute_genquery',
        'query': f"select COLL_NAME, COLL_CREATE_TIME where COLL_ID = '{coll_id}'"
    })

    if r.status_code != 200:
        app.logger.error('Error retrieving collection information.')
        abort(500)

    r_json = r.json()
    if r_json['irods_response']['status_code'] < 0:
        app.logger.error('Error retrieving collection information.')
        abort(500)

    logical_path = r_json['rows'][0][0]

    # Update the timestamps to be in ISO8601 format.
    # The conversion to an integer ignores leading zeros. 
    ctime = datetime.datetime.utcfromtimestamp(int(r_json['rows'][0][1]))

    app.logger.debug(f'logical_path = [{logical_path}]')
    app.logger.debug(f'ctime = [{ctime}]')

    r = requests.get(IRODS_HTTP_API_URL + '/collections', headers={'Authorization': f'Bearer {session["bearer_token"]}'}, params={
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

    r_json.pop('irods_response')
    r_json['inheritance_enabled'] = 'yes' if r_json['inheritance_enabled'] == True else 'no'
    r_json['created_at'] = ctime
    r_json['modified_at'] = datetime.datetime.utcfromtimestamp(r_json['modified_at'])

    return render_template(
        'collection_info.html',
        title='Collection Information',
        logical_path=logical_path,
        coll_id=coll_id,
        coll_info=r_json
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

@app.route('/add-metadata', methods=["POST"])
def add_metadata():
    if 'username' not in session:
        abort(401)

    if request.form.get('entity_type', None) != 'data_object':
        app.logger.error('only data objects are supported.')
        abort(400)

    r = requests.post(IRODS_HTTP_API_URL + '/data-objects', headers={'Authorization': f'Bearer {session["bearer_token"]}'}, data={
        'op': 'modify_metadata',
        'lpath': request.form.get('lpath', None),
        'operations': json.dumps([{
            'operation': 'add',
            'attribute': request.form.get('attribute', None),
            'value': request.form.get('value', None),
            'units': request.form.get('units', None)
        }])
    })

    if r.status_code != 200:
        app.logger.error('Error adding metadata to data object.')
        abort(500)

    r_json = r.json()
    if r_json['irods_response']['status_code'] < 0:
        app.logger.error('Error adding metadata to data object.')
        abort(500)

    return redirect(url_for('data_object_info', data_id=request.form.get('data_id')))

@app.route('/remove-metadata', methods=["POST"])
def remove_metadata():
    if 'username' not in session:
        abort(401)

    if request.form.get('entity_type', None) != 'data_object':
        app.logger.error('only data objects are supported.')
        abort(400)

    r = requests.post(IRODS_HTTP_API_URL + '/data-objects', headers={'Authorization': f'Bearer {session["bearer_token"]}'}, data={
        'op': 'modify_metadata',
        'lpath': request.form.get('lpath', None),
        'operations': json.dumps([{
            'operation': 'remove',
            'attribute': request.form.get('attribute', None),
            'value': request.form.get('value', None),
            'units': request.form.get('units', None)
        }])
    })

    if r.status_code != 200:
        app.logger.error('Error removing metadata from data object.')
        abort(500)

    r_json = r.json()
    if r_json['irods_response']['status_code'] < 0:
        app.logger.error('Error removing metadata from data object.')
        abort(500)

    return redirect(url_for('data_object_info', data_id=request.form.get('data_id')))

@app.route('/add-permission', methods=["POST"])
def add_permission():
    if 'username' not in session:
        abort(401)

    app.logger.debug(f'data_id     = [{request.form.get("data_id", None)}]')
    app.logger.debug(f'lpath       = [{request.form.get("lpath", None)}]')
    app.logger.debug(f'entity_name = [{request.form.get("entity_name", None)}]')
    app.logger.debug(f'permission  = [{request.form.get("permission", None)}]')

    r = requests.post(IRODS_HTTP_API_URL + '/data-objects', headers={'Authorization': f'Bearer {session["bearer_token"]}'}, data={
        'op': 'modify_permissions',
        'lpath': request.form.get('lpath', None),
        'operations': json.dumps([{
            'entity_name': request.form.get('entity_name', None),
            'acl': request.form.get('permission', None)
        }])
    })

    if r.status_code != 200:
        app.logger.error('(http) Error adding permission to data object.')
        abort(500)

    r_json = r.json()
    if r_json['irods_response']['status_code'] < 0:
        app.logger.error('(irods) Error adding permission to data object.')
        abort(500)

    return redirect(url_for('data_object_info', data_id=request.form.get('data_id')))

@app.route('/remove-permission', methods=["POST"])
def remove_permission():
    if 'username' not in session:
        abort(401)

    app.logger.debug(f'lpath       = [{request.form.get("lpath", None)}]')
    app.logger.debug(f'entity_name = [{request.form.get("entity_name", None)}]')

    r = requests.post(IRODS_HTTP_API_URL + '/data-objects', headers={'Authorization': f'Bearer {session["bearer_token"]}'}, data={
        'op': 'modify_permissions',
        'lpath': request.form.get('lpath', None),
        'operations': json.dumps([{
            'entity_name': request.form.get('entity_name', None),
            'acl': 'null'
        }])
    })

    if r.status_code != 200:
        app.logger.error('(http) Error removing permission from data object.')
        abort(500)

    r_json = r.json()
    if r_json['irods_response']['status_code'] < 0:
        app.logger.error('(irods) Error removing permission from data object.')
        abort(500)

    return redirect(url_for('data_object_info', data_id=request.form.get('data_id')))

@app.get('/about')
def about():
    return render_template('about.html', title='About')

@app.get('/contact')
def contact():
    return render_template('contact.html', title='Contact')
