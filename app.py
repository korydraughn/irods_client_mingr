from flask import Flask, render_template, request, abort, session

import requests
import os

app = Flask(__name__)

# TODO Required for session support. Use python secrets module. Flask has more docs about this too.
app.secret_key = 'THIS NEEDS TO BE GENERATED ON STARTUP'

IRODS_HTTP_API_URL = 'http://localhost:9000/irods-http-api/0.3.0'
IRODS_ZONE_NAME = 'tempZone'

def to_filesystem_page(session, collection):
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
        current_collection=coll_path,
        collections=collections,
        data_objects=r_json['rows']
    )

@app.route('/', methods=['POST', 'GET'])
@app.route('/login/', methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        app.logger.debug('Received GET request on /login')
        # TODO Embed secure random token in form element to block XSS and other attacks.
        return render_template('index.html')

    if request.method == 'POST':
        username = request.form['username']
        app.logger.debug(f'Authenticating user [{username}]')
        r = requests.post(IRODS_HTTP_API_URL + '/authenticate', auth=(
            username,
            request.form['password']
        ))

        if r.status_code != 200:
            app.logger.error('Invalid username and/or password.')
            abort(401) # TODO Use a dedicated page.

        app.logger.debug('Authentication was successful.')

        # Start a new session for the user and redirect them to the filesystem page.
        session['username'] = username
        session['bearer_token'] = r.text
        return to_filesystem_page(session, f'/{IRODS_ZONE_NAME}/home/{username}')

@app.route('/filesystem/', methods=['POST'])
def filesystem():
    collection = request.form['collection']
    app.logger.debug(f'collection = [{collection}]')
    return to_filesystem_page(session, collection)

@app.route('/data-object-info/', methods=['GET'])
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
        logical_path=logical_path,
        data_id=data_id,
        replicas=replicas,
        permissions=r_json['permissions']
    )

@app.route('/data-object-info-X/', methods=['POST'])
def data_object_infoX():
    data_id = request.form['data_id']
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
        logical_path=logical_path,
        data_id=data_id,
        replicas=replicas,
        permissions=r_json['permissions']
    )
