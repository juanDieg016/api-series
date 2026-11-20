from flask import (
    Flask,
    jsonify,
    request,
    send_from_directory,
    render_template
)

import os
import datetime
import jwt

from dotenv import load_dotenv
from functools import wraps
from pymongo import MongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError, PyMongoError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

load_dotenv(
    os.path.join(BASE_DIR, '.env'),
    override=True
)

VIDEOS_DIR = os.path.join(BASE_DIR, 'videos')

EXTENSIONES_VIDEO = (
    '.mp4',
    '.webm',
    '.mkv'
)

MONGO_URI = os.environ.get(
    'MONGO_URI',
    'mongodb://localhost:27017'
)

DB_NAME = os.environ.get(
    'MONGO_DB',
    'series_db'
)


app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get(
    'SECRET_KEY',
    'clave_demo_series_2026_123456'
)

app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024


USUARIOS_INICIALES = {

    'admin': {
        'clave': os.environ.get(
            'ADMIN_PASSWORD',
            'admin123'
        ),
        'rol': 'admin'
    },

    'teacher': {
        'clave': 'demo123',
        'rol': 'usuario'
    }
}


_client = None


def get_db():

    global _client

    if _client is None:

        _client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=5000
        )

    return _client[DB_NAME]


def init_db():

    db = get_db()

    db.users.create_index(
        'username',
        unique=True
    )

    db.series.create_index(
        'id',
        unique=True
    )

    for username, datos in USUARIOS_INICIALES.items():

        usuario = db.users.find_one({
            'username': username
        })

        if usuario is None:

            db.users.insert_one({

                'username': username,

                'password_hash':
                    generate_password_hash(
                        datos['clave']
                    ),

                'rol': datos['rol']
            })

        else:

            db.users.update_one(
                {'username': username},
                {
                    '$set': {
                        'rol': datos['rol']
                    }
                }
            )

    os.makedirs(
        VIDEOS_DIR,
        exist_ok=True
    )


def siguiente_id():

    doc = get_db().counters.find_one_and_update(

        {'_id': 'series'},

        {
            '$inc': {
                'seq': 1
            }
        },

        upsert=True,

        return_document=ReturnDocument.AFTER
    )

    return doc['seq']


@app.errorhandler(PyMongoError)
def error_base_datos(e):

    return jsonify({
        'error': 'Base de datos no disponible'
    }), 503


@app.errorhandler(413)
def archivo_demasiado_grande(e):

    return jsonify({
        'error': 'El archivo supera el tamaño máximo de 500 MB'
    }), 413


@app.route('/')
def root():

    return render_template(
        'index.html'
    )


@app.route('/mi-cuenta')
def mi_cuenta():

    return render_template(
        'account.html'
    )


@app.route('/login', methods=['POST'])
def login():

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):

        return jsonify({
            'error': 'Envía un objeto JSON'
        }), 400

    username = data.get('username')
    clave = data.get('clave')

    if (
        not isinstance(username, str)
        or not isinstance(clave, str)
    ):

        return jsonify({
            'error':
                'username y clave son obligatorios'
        }), 400

    username = username.strip()

    usuario = get_db().users.find_one({
        'username': username
    })

    if (
        usuario
        and check_password_hash(
            usuario['password_hash'],
            clave
        )
    ):

        token = jwt.encode({

            'user': username,

            'rol': usuario['rol'],

            'exp':
                datetime.datetime.now(
                    datetime.timezone.utc
                )
                +
                datetime.timedelta(
                    hours=1
                )

        },
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )

        return jsonify({

            'token': token,

            'rol': usuario['rol'],

            'username': username

        }), 200

    return jsonify({
        'error': 'Credenciales inválidas'
    }), 401


@app.route('/registro', methods=['POST'])
def registro():

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):

        return jsonify({
            'error': 'Envía un objeto JSON'
        }), 400

    username = data.get('username')
    clave = data.get('clave')

    if (
        not isinstance(username, str)
        or not 3 <= len(
            username.strip()
        ) <= 30
    ):

        return jsonify({
            'error':
                'username debe tener entre '
                '3 y 30 caracteres'
        }), 400

    if (
        not isinstance(clave, str)
        or len(clave) < 6
    ):

        return jsonify({
            'error':
                'clave debe tener al menos '
                '6 caracteres'
        }), 400

    username = username.strip()

    try:

        get_db().users.insert_one({

            'username': username,

            'password_hash':
                generate_password_hash(
                    clave
                ),

            'rol': 'usuario'
        })

    except DuplicateKeyError:

        return jsonify({
            'error': 'El usuario ya existe'
        }), 409

    return jsonify({
        'message': 'Usuario registrado'
    }), 201


def verificar_token():

    auth = request.headers.get(
        'Authorization',
        ''
    )

    partes = auth.split()

    if (
        len(partes) != 2
        or partes[0].lower() != 'bearer'
    ):

        return None, (
            jsonify({
                'error':
                    'Usa Bearer seguido del token'
            }),
            401
        )

    try:

        payload = jwt.decode(

            partes[1],

            app.config['SECRET_KEY'],

            algorithms=['HS256'],

            options={
                'require': [
                    'exp',
                    'user'
                ]
            }
        )

    except jwt.ExpiredSignatureError:

        return None, (
            jsonify({
                'error': 'Token expirado'
            }),
            401
        )

    except jwt.InvalidTokenError:

        return None, (
            jsonify({
                'error': 'Token inválido'
            }),
            401
        )

    return payload, None


def token_required(f):

    @wraps(f)
    def decorador(
        *args,
        **kwargs
    ):

        _, error = verificar_token()

        if error:
            return error

        return f(
            *args,
            **kwargs
        )

    return decorador


def admin_required(f):

    @wraps(f)
    def decorador(
        *args,
        **kwargs
    ):

        payload, error = verificar_token()

        if error:
            return error

        if payload.get('rol') != 'admin':

            return jsonify({
                'error':
                    'Solo un administrador '
                    'puede realizar esta acción'
            }), 403

        return f(
            *args,
            **kwargs
        )

    return decorador


@app.route('/me', methods=['GET'])
@token_required
def me():

    payload, error = verificar_token()

    if error:
        return error

    return jsonify({

        'username':
            payload.get('user'),

        'rol':
            payload.get('rol')

    }), 200


@app.route('/me/password', methods=['PUT'])
@token_required
def cambiar_password():

    payload, error = verificar_token()

    if error:
        return error

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):

        return jsonify({
            'error': 'Envía un objeto JSON'
        }), 400

    clave_actual = data.get(
        'clave_actual'
    )

    clave_nueva = data.get(
        'clave_nueva'
    )

    if (
        not isinstance(clave_actual, str)
        or not clave_actual
    ):

        return jsonify({
            'error':
                'La contraseña actual es obligatoria'
        }), 400

    if (
        not isinstance(clave_nueva, str)
        or len(clave_nueva) < 6
    ):

        return jsonify({
            'error':
                'La nueva contraseña debe tener '
                'al menos 6 caracteres'
        }), 400

    username = payload.get('user')

    usuario = get_db().users.find_one({
        'username': username
    })

    if usuario is None:

        return jsonify({
            'error':
                'Usuario no encontrado'
        }), 404

    if not check_password_hash(
        usuario['password_hash'],
        clave_actual
    ):

        return jsonify({
            'error':
                'La contraseña actual es incorrecta'
        }), 400

    if check_password_hash(
        usuario['password_hash'],
        clave_nueva
    ):

        return jsonify({
            'error':
                'La nueva contraseña debe ser diferente '
                'a la contraseña actual'
        }), 400

    get_db().users.update_one(

        {
            'username': username
        },

        {
            '$set': {

                'password_hash':
                    generate_password_hash(
                        clave_nueva
                    )
            }
        }
    )

    return jsonify({
        'message':
            'Contraseña actualizada correctamente'
    }), 200


def validar_serie(data):

    if not isinstance(data, dict):

        return 'Envía un objeto JSON'

    for campo in (
        'titulo',
        'genero',
        'plataforma'
    ):

        valor = data.get(campo)

        if (
            not isinstance(valor, str)
            or not valor.strip()
        ):

            return (
                f'{campo} debe ser '
                'un texto no vacío'
            )

    temporadas = data.get(
        'temporadas'
    )

    if (
        type(temporadas) is not int
        or temporadas <= 0
        or temporadas > 100
    ):

        return (
            'temporadas debe ser un entero '
            'entre 1 y 100'
        )

    archivo = data.get('archivo')

    if archivo is not None:

        if (
            not isinstance(archivo, str)
            or not archivo.strip()
        ):

            return (
                'archivo debe ser un texto '
                'no vacío o no enviarse'
            )

        archivo = archivo.strip()

        if archivo != os.path.basename(
            archivo
        ):

            return (
                'archivo debe ser solo un '
                'nombre de archivo, sin rutas'
            )

        if not archivo.lower().endswith(
            EXTENSIONES_VIDEO
        ):

            return (
                'archivo debe terminar en '
                +
                ', '.join(
                    EXTENSIONES_VIDEO
                )
            )

    return None


def documento_serie(data):

    archivo = data.get('archivo')

    return {

        'titulo':
            data['titulo'].strip(),

        'genero':
            data['genero'].strip(),

        'plataforma':
            data['plataforma'].strip(),

        'temporadas':
            data['temporadas'],

        'archivo':
            archivo.strip()
            if isinstance(
                archivo,
                str
            )
            else None
    }


def archivo_video_valido(nombre):

    if not nombre:
        return False

    return nombre.lower().endswith(
        EXTENSIONES_VIDEO
    )


@app.route('/series', methods=['GET'])
def list_series():

    buscar = request.args.get(
        'buscar',
        ''
    ).strip()

    filtro = {}

    if buscar:

        filtro = {
            '$or': [

                {
                    'titulo': {
                        '$regex': buscar,
                        '$options': 'i'
                    }
                },

                {
                    'genero': {
                        '$regex': buscar,
                        '$options': 'i'
                    }
                },

                {
                    'plataforma': {
                        '$regex': buscar,
                        '$options': 'i'
                    }
                }
            ]
        }

    series = list(

        get_db().series.find(
            filtro,
            {'_id': 0}
        ).sort(
            'id',
            1
        )
    )

    return jsonify(
        series
    ), 200


@app.route(
    '/series/<int:serie_id>',
    methods=['GET']
)
def get_serie(serie_id):

    serie = get_db().series.find_one(
        {'id': serie_id},
        {'_id': 0}
    )

    if serie is None:

        return jsonify({
            'error':
                'Serie no encontrada'
        }), 404

    return jsonify(
        serie
    ), 200


@app.route(
    '/series',
    methods=['POST']
)
@admin_required
def create_serie():

    data = request.get_json(
        silent=True
    )

    error = validar_serie(
        data
    )

    if error:

        return jsonify({
            'error': error
        }), 400

    nuevo_id = siguiente_id()

    doc = documento_serie(
        data
    )

    doc['id'] = nuevo_id

    get_db().series.insert_one(
        doc
    )

    return jsonify({

        'id': nuevo_id,

        'message':
            'Serie creada'

    }), 201


@app.route(
    '/series/<int:serie_id>',
    methods=['PUT']
)
@admin_required
def update_serie(serie_id):

    data = request.get_json(
        silent=True
    )

    error = validar_serie(
        data
    )

    if error:

        return jsonify({
            'error': error
        }), 400

    resultado = (
        get_db()
        .series
        .update_one(

            {'id': serie_id},

            {
                '$set':
                    documento_serie(
                        data
                    )
            }
        )
    )

    if resultado.matched_count == 0:

        return jsonify({
            'error':
                'Serie no encontrada'
        }), 404

    return jsonify({
        'message':
            'Serie actualizada'
    }), 200


@app.route(
    '/series/<int:serie_id>',
    methods=['DELETE']
)
@admin_required
def delete_serie(serie_id):

    serie = get_db().series.find_one({
        'id': serie_id
    })

    if serie is None:

        return jsonify({
            'error':
                'Serie no encontrada'
        }), 404

    resultado = (
        get_db()
        .series
        .delete_one({
            'id': serie_id
        })
    )

    if resultado.deleted_count == 0:

        return jsonify({
            'error':
                'Serie no encontrada'
        }), 404

    return jsonify({
        'message':
            'Serie eliminada'
    }), 200


@app.route(
    '/series/<int:serie_id>/video',
    methods=['POST']
)
@admin_required
def subir_video(serie_id):

    serie = get_db().series.find_one({
        'id': serie_id
    })

    if serie is None:

        return jsonify({
            'error':
                'Serie no encontrada'
        }), 404

    if 'video' not in request.files:

        return jsonify({
            'error':
                'No se envió ningún archivo'
        }), 400

    video = request.files['video']

    if not video.filename:

        return jsonify({
            'error':
                'Selecciona un archivo'
        }), 400

    nombre = secure_filename(
        video.filename
    )

    if not archivo_video_valido(
        nombre
    ):

        return jsonify({
            'error':
                'Formato de video no permitido. '
                'Usa MP4, WEBM o MKV'
        }), 400

    os.makedirs(
        VIDEOS_DIR,
        exist_ok=True
    )

    nombre_final = (
        f'{serie_id}_{nombre}'
    )

    ruta = os.path.join(
        VIDEOS_DIR,
        nombre_final
    )

    video.save(
        ruta
    )

    archivo_anterior = serie.get(
        'archivo'
    )

    if archivo_anterior:

        ruta_anterior = os.path.join(
            VIDEOS_DIR,
            archivo_anterior
        )

        if (
            os.path.isfile(
                ruta_anterior
            )
            and ruta_anterior != ruta
        ):

            try:

                os.remove(
                    ruta_anterior
                )

            except OSError:
                pass

    get_db().series.update_one(

        {'id': serie_id},

        {
            '$set': {
                'archivo':
                    nombre_final
            }
        }
    )

    return jsonify({

        'message':
            'Video cargado correctamente',

        'archivo':
            nombre_final

    }), 200


def servir_video(
    serie_id,
    como_descarga
):

    serie = get_db().series.find_one(
        {'id': serie_id},
        {'_id': 0}
    )

    if serie is None:

        return jsonify({
            'error':
                'Serie no encontrada'
        }), 404

    if not serie.get('archivo'):

        return jsonify({
            'error':
                'Esta serie no tiene '
                'video asociado'
        }), 404

    ruta = os.path.join(
        VIDEOS_DIR,
        serie['archivo']
    )

    if not os.path.isfile(
        ruta
    ):

        return jsonify({
            'error':
                'El archivo de video '
                'no existe en el servidor'
        }), 404

    return send_from_directory(

        VIDEOS_DIR,

        serie['archivo'],

        as_attachment=
            como_descarga,

        conditional=True
    )


@app.route(
    '/series/<int:serie_id>/descargar',
    methods=['GET']
)
def descargar_serie(serie_id):

    return servir_video(
        serie_id,
        como_descarga=True
    )


@app.route(
    '/series/<int:serie_id>/ver',
    methods=['GET']
)
def ver_serie(serie_id):

    return servir_video(
        serie_id,
        como_descarga=False
    )


if __name__ == '__main__':

    init_db()

    app.run(
        debug=True
    )