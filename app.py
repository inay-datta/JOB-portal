from flask import Flask, request, jsonify, abort
from flask_pymongo import PyMongo
import jwt
import bcrypt
import datetime
from functools import wraps
from flask_cors import CORS  # Import CORS

app = Flask(__name__)

# Configure MongoDB
app.config['MONGO_URI'] = 'mongodb://localhost:27017/JobPortal'
mongo = PyMongo(app)

# Secret key for JWT encoding/decoding
SECRET_KEY = 'vinaydatta$@123'

CORS(app, resources={r"/*": {"origins": "*"}})

# Helper function to generate a sequential ID for different collections
def get_next_id(collection_name):
    counter = mongo.db.counters.find_one_and_update(
        {'_id': collection_name},
        {'$inc': {'seq': 1}},
        return_document=True,
        upsert=True
    )
    return counter['seq']

# Decorator to protect routes
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403

        try:
            # Extract token part after 'Bearer'
            token = token.split(" ")[1]  
            # Decode the token using your SECRET_KEY
            data = jwt.decode(token,SECRET_KEY , algorithms=['HS256'])
            
            # Fetch the user from the database using information from token
            current_user = mongo.db.users.find_one({'username': data['username']})
            if not current_user:
                raise jwt.InvalidTokenError

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        return f(current_user, *args, **kwargs)
    
    return decorated

# Role-based access control
def recruiter_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        current_user, *args = args
        if 'recruiter' not in current_user.get('userType', []):
            return jsonify({'message': 'Access denied. Recruiter role required.'}), 403
        return f(current_user, *args, **kwargs)
    
    return decorated

# Register endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user_type = data.get('user_type', [])  # Get user_type or default to an empty list

    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400

    # Check if user already exists
    user = mongo.db.users.find_one({'username': username})
    if user:
        return jsonify({'message': 'User already exists'}), 400

    # Get the next user_id
    user_id = mongo.db.users.count_documents({}) + 1  # Sequential ID based on the current count

    # Hash password and store user
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    mongo.db.users.insert_one({
        'username': username,
        'password': hashed_password,
        'user_id': user_id,  # Add user_id
        'userType': user_type  # Include user_type
    })

    return jsonify({'message': 'User registered successfully'}), 201

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400

    # Check if user exists
    user = mongo.db.users.find_one({'username': username})
    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401

    # Verify password
    if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({'message': 'Invalid credentials'}), 401

    # Create JWT token with userType
    token = jwt.encode({
        'username': username,
        'userType': user.get('userType', []),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, SECRET_KEY, algorithm='HS256')

    return jsonify({'token': token})

# Protected endpoint for users
@app.route('/protected', methods=['GET'])
@token_required
def protected_route(current_user):
    return jsonify({
        'message': 'This is a protected route!',
        'user': current_user['username'],
        'user_id': current_user.get('user_id')  # Include user_id
    })

# Endpoint to get user details
@app.route('/getuser', methods=['GET'])
@token_required
def get_user_details(current_user):
    return jsonify({
        'username': current_user['username'],
        'user_id': current_user.get('user_id'),  # Include user_id
        'user_type': current_user.get('userType', [])
    })

# Update user details endpoint
@app.route('/updateuser', methods=['PUT'])
@token_required
def update_user(current_user):
    data = request.json
    user_type = data.get('user_type')
    new_password = data.get('password')

    update_fields = {}
    if user_type is not None:
        update_fields['userType'] = user_type
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        update_fields['password'] = hashed_password

    if not update_fields:
        return jsonify({'message': 'No data provided for update'}), 400

    mongo.db.users.update_one({'username': current_user['username']}, {'$set': update_fields})

    return jsonify({'message': 'User details updated successfully'})

# Delete user endpoint
@app.route('/deleteuser', methods=['DELETE'])
@token_required
def delete_user(current_user):
    mongo.db.users.delete_one({'username': current_user['username']})
    return jsonify({'message': 'User deleted successfully'})

# Create organization
@app.route('/createorg', methods=['POST'])
@token_required
@recruiter_required
def create_organization(current_user):
    data = request.json
    if not data or 'name' not in data:
        abort(400, description="Invalid input")
    
    new_id = get_next_id('organization_id')
    new_org = {
        'id': new_id,
        'name': data.get('name'),
        'address': data.get('address', []),
        'gst': data.get('gst', ''),
        'foundationYear': data.get('foundationYear', ''),
        'funding': data.get('funding', []),
        'created_by': current_user['username']  # Associate organization with the user who created it
    }
    result = mongo.db.organizations.insert_one(new_org)
    new_org['_id'] = str(result.inserted_id)  # Include MongoDB's _id in the response
    return jsonify(new_org), 201

# Get organization by ID
@app.route('/getorg/<int:org_id>', methods=['GET'])
@token_required
def get_organization(current_user, org_id):
    org = mongo.db.organizations.find_one({'id': org_id, 'created_by': current_user['username']})
    if org is None:
        abort(404, description="Organization not found or not authorized")
    org['_id'] = str(org['_id'])  # Convert ObjectId to string for response
    return jsonify(org)

# Update organization by ID
@app.route('/updateorg/<int:org_id>', methods=['PUT'])
@token_required
def update_organization(current_user, org_id):
    data = request.json
    result = mongo.db.organizations.update_one(
        {'id': org_id, 'created_by': current_user['username']},
        {'$set': {
            'name': data.get('name', ''),
            'address': data.get('address', []),
            'gst': data.get('gst', ''),
            'foundationYear': data.get('foundationYear', ''),
            'funding': data.get('funding', [])
        }}
    )
    if result.matched_count == 0:
        abort(404, description="Organization not found or not authorized")
    
    updated_org = mongo.db.organizations.find_one({'id': org_id, 'created_by': current_user['username']})
    updated_org['_id'] = str(updated_org['_id'])  # Convert ObjectId to string for response
    return jsonify(updated_org)

# Delete organization by ID
@app.route('/deleteorg/<int:org_id>', methods=['DELETE'])
@token_required
def delete_organization(current_user, org_id):
    result = mongo.db.organizations.delete_one({'id': org_id, 'created_by': current_user['username']})
    if result.deleted_count == 0:
        abort(404, description="Organization not found or not authorized")
    return '', 204

# Create job
@app.route('/createjob', methods=['POST'])
@token_required
def create_job(current_user):
    data = request.json
    if not data or 'description' not in data or 'organizationId' not in data or 'expiryDays' not in data:
        abort(400, description="Invalid input")

    # Verify that the organizationId exists
    organization_id = data.get('organizationId')
    if not mongo.db.organizations.find_one({'id': organization_id}):
        abort(400, description="Invalid organizationId")

    # Calculate the expiration date based on the number of days
    expiry_days = int(data.get('expiryDays'))
    expiry_date = datetime.datetime.utcnow() + datetime.timedelta(days=expiry_days)

    new_id = get_next_id('job_id')
    new_job = {
        'id': new_id,
        'jobId': data.get('jobId', ''),
        'organizationId': organization_id,
        'description': data.get('description'),
        'location': data.get('location', []),
        'salaryRange': data.get('salaryRange', ''),
        'createdDate': data.get('createdDate', datetime.datetime.utcnow().isoformat()),
        'expiryDate': expiry_date.isoformat(),
        'recruiterId': current_user.get('user_id'),
        'status': data.get('status', 'open')
    }
    result = mongo.db.jobs.insert_one(new_job)
    new_job['_id'] = str(result.inserted_id)  # Include MongoDB's _id in the response
    return jsonify(new_job), 201


# Get job by ID
@app.route('/getjob/<int:job_id>', methods=['GET'])
@token_required
def get_job(current_user, job_id):
    job = mongo.db.jobs.find_one({'id': job_id, 'recruiterId': current_user.get('user_id')})
    if job is None:
        abort(404, description="Job not found or not authorized")

    # Check if the job is expired
    if datetime.datetime.utcnow() > datetime.datetime.fromisoformat(job['expiryDate']):
        return jsonify({'message': 'Job has expired'}), 410  # 410 Gone

    job['_id'] = str(job['_id'])  # Convert ObjectId to string for response
    return jsonify(job)


# Update job by ID
@app.route('/updatejob/<int:job_id>', methods=['PUT'])
@token_required
def update_job(current_user, job_id):
    data = request.json
    result = mongo.db.jobs.update_one(
        {'id': job_id, 'recruiterId': current_user.get('user_id')},
        {'$set': {
            'jobId': data.get('jobId', ''),
            'organizationId': data.get('organizationId', ''),
            'description': data.get('description', ''),
            'location': data.get('location', []),
            'salaryRange': data.get('salaryRange', ''),
            'createdDate': data.get('createdDate', ''),
            'expiryDate': data.get('expiryDate', ''),
            'status': data.get('status', 'open')
        }}
    )
    if result.matched_count == 0:
        abort(404, description="Job not found or not authorized")
    
    updated_job = mongo.db.jobs.find_one({'id': job_id, 'recruiterId': current_user.get('user_id')})
    updated_job['_id'] = str(updated_job['_id'])  # Convert ObjectId to string for response
    return jsonify(updated_job)

# Delete job by ID
@app.route('/deletejob/<int:job_id>', methods=['DELETE'])
@token_required
def delete_job(current_user, job_id):
    result = mongo.db.jobs.delete_one({'id': job_id, 'recruiterId': current_user.get('user_id')})
    if result.deleted_count == 0:
        abort(404, description="Job not found or not authorized")
    return '', 204

# Create profile
@app.route('/createprofile', methods=['POST'])
@token_required
def create_profile(current_user):
    data = request.json
    if not data or 'skills' not in data or 'currentAdd' not in data or 'PermanentAdd' not in data:
        abort(400, description="Invalid input")

    new_id = get_next_id('profile_id')
    new_profile = {
        'id': new_id,
        'userId': current_user.get('user_id'),
        'skills': data.get('skills', []),
        'currentAdd': data.get('currentAdd'),
        'PermanentAdd': data.get('PermanentAdd'),
        'jobhistory': data.get('jobhistory', []),
        'preferredlocation': data.get('preferredlocation', [])
    }
    result = mongo.db.profiles.insert_one(new_profile)
    new_profile['_id'] = str(result.inserted_id)  # Include MongoDB's _id in the response
    return jsonify(new_profile), 201

# Get profile by ID
@app.route('/getprofile/<int:profile_id>', methods=['GET'])
@token_required
def get_profile(current_user, profile_id):
    profile = mongo.db.profiles.find_one({'id': profile_id, 'userId': current_user.get('user_id')})
    if profile is None:
        abort(404, description="Profile not found or not authorized")
    profile['_id'] = str(profile['_id'])  # Convert ObjectId to string for response
    return jsonify(profile)

# Update profile by ID
@app.route('/updateprofile/<int:profile_id>', methods=['PUT'])
@token_required
def update_profile(current_user, profile_id):
    data = request.json
    result = mongo.db.profiles.update_one(
        {'id': profile_id, 'userId': current_user.get('user_id')},
        {'$set': {
            'skills': data.get('skills', []),
            'currentAdd': data.get('currentAdd', ''),
            'PermanentAdd': data.get('PermanentAdd', ''),
            'jobhistory': data.get('jobhistory', []),
            'preferredlocation': data.get('preferredlocation', [])
        }}
    )
    if result.matched_count == 0:
        abort(404, description="Profile not found or not authorized")
    
    updated_profile = mongo.db.profiles.find_one({'id': profile_id, 'userId': current_user.get('user_id')})
    updated_profile['_id'] = str(updated_profile['_id'])  # Convert ObjectId to string for response
    return jsonify(updated_profile)

# Delete profile by ID
@app.route('/deleteprofile/<int:profile_id>', methods=['DELETE'])
@token_required
def delete_profile(current_user, profile_id):
    result = mongo.db.profiles.delete_one({'id': profile_id, 'userId': current_user.get('user_id')})
    if result.deleted_count == 0:
        abort(404, description="Profile not found or not authorized")
    return '', 204
def is_candidate(user):
    return 'candidate' in user.get('userType', [])

# Create job application
@app.route('/createapplication', methods=['POST'])
@token_required
def create_application(current_user):
    if not is_candidate(current_user):
        abort(403, description="Only candidates can create job applications")

    data = request.json
    if not data or 'jobId' not in data or 'candidateId' not in data:
        abort(400, description="Invalid input")

    # Ensure the candidateId matches the current user
    candidate_id = data.get('candidateId')
    if candidate_id != current_user.get('user_id'):
        abort(403, description="Unauthorized to create application for this candidate")

    new_id = get_next_id('application_id')
    new_application = {
        'id': new_id,
        'jobId': data.get('jobId'),
        'candidateId': candidate_id,
        'applieddate': data.get('applieddate', datetime.datetime.utcnow().isoformat()),
        'status': data.get('status', 'applied')
    }
    result = mongo.db.jobApplications.insert_one(new_application)
    new_application['_id'] = str(result.inserted_id)  # Include MongoDB's _id in the response
    return jsonify(new_application), 201

# Get job application by ID
@app.route('/getapplication/<int:application_id>', methods=['GET'])
@token_required
def get_application(current_user, application_id):
    if not is_candidate(current_user):
        abort(403, description="Only candidates can view job applications")

    application = mongo.db.jobApplications.find_one({'id': application_id})
    if application is None:
        abort(404, description="Application not found")
    application['_id'] = str(application['_id'])  # Convert ObjectId to string for response
    return jsonify(application)

# Update job application by ID
@app.route('/updateapplication/<int:application_id>', methods=['PUT'])
@token_required
def update_application(current_user, application_id):
    if not is_candidate(current_user):
        abort(403, description="Only candidates can update job applications")

    data = request.json
    result = mongo.db.jobApplications.update_one(
        {'id': application_id},
        {'$set': {
            'jobId': data.get('jobId', ''),
            'candidateId': data.get('candidateId', ''),
            'applieddate': data.get('applieddate', ''),
            'status': data.get('status', 'applied')
        }}
    )
    if result.matched_count == 0:
        abort(404, description="Application not found")

    updated_application = mongo.db.jobApplications.find_one({'id': application_id})
    updated_application['_id'] = str(updated_application['_id'])  # Convert ObjectId to string for response
    return jsonify(updated_application)

# Delete job application by ID
@app.route('/deleteapplication/<int:application_id>', methods=['DELETE'])
@token_required
def delete_application(current_user, application_id):
    if not is_candidate(current_user):
        abort(403, description="Only candidates can delete job applications")

    result = mongo.db.jobApplications.delete_one({'id': application_id})
    if result.deleted_count == 0:
        abort(404, description="Application not found")
    return '', 204


@app.route('/totalcan', methods=['GET'])
@token_required
def get_candidates(current_user):
    page = int(request.args.get('page', 1))  # Default to page 1
    per_page = int(request.args.get('per_page', 10))  # Default to 10 candidates per page

    # Validate pagination parameters
    if page < 1 or per_page < 1:
        abort(400, description="Invalid pagination parameters")

    # Calculate the total number of candidates
    total_candidates = mongo.db.users.count_documents({'userType': 'candidate'})

    # Retrieve candidates with pagination
    candidates_cursor = mongo.db.users.find({'userType': 'candidate'})
    candidates = list(candidates_cursor.skip((page - 1) * per_page).limit(per_page))

    # Convert ObjectId to string
    for candidate in candidates:
        candidate['_id'] = str(candidate['_id'])
        for key in candidate:
            if isinstance(candidate[key], bytes):
                candidate[key] = candidate[key].decode('utf-8')
    

    return jsonify({
        'total_candidates': total_candidates,
        'current_page': page,
        'total_pages': (total_candidates + per_page - 1) // per_page,
        'candidates': candidates
    })
if __name__ == '__main__':
    app.run(debug=True, port=7002)
