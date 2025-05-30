import io
import joblib
from django.contrib import messages
from django.contrib.auth import authenticate, login ,logout
from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.core.mail import send_mail
from django.db import IntegrityError
from django.shortcuts import render, redirect
from django.utils import timezone

from service.models import UserProfile ,MLProject,MLProjectFile
import os, random , zipfile
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.admin.views.decorators import staff_member_required
from django.http import JsonResponse, HttpResponse
import pandas as pd
import pickle
from django.http import FileResponse, Http404





# ... your imports remain unchanged ...

# Utility: Send verification code
def send_ver_code(email):
    ver_code = str(random.randint(100000, 999999))
    subject = "Verification Code For Your Retre Account"
    message = f"Verification Code: {ver_code}"
    sender = 'retre.platform@gmail.com'
    try:
        send_mail(subject, message, sender, [email])
        return ver_code
    except Exception as e:
        print(f"Email sending failed: {e}")
        return None
def send_email_msg(approve,username,email):
    sender = 'retre.platform@gmail.com'
    sub="Project Rejected"
    msg=username + " Your Project has been Rejected Due To Policy Violation.\n For More Information Contact Admin\nThank You\n-Admin"
    if approve:
        sub="Project Approved"
        msg=username + " Your Project has been Approved For Public View. Do Connect and Provide more Projects\nThank You\n-Admin"
    try:
        send_mail(sub,msg,sender,[email])
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False
    return True

def creator_required(view_func):
    @login_required
    def wrapper(request, *args, **kwargs):
        try:
            profile = UserProfile.objects.get(user=request.user)
            if profile.role == 'creator':
                return view_func(request, *args, **kwargs)
        except UserProfile.DoesNotExist:
            pass
        return redirect('/')  # Or show a custom error page
    return wrapper

# Registration
def index(request):
    context = {
        'unamecheck': True,
        'emailcheck': True,
        'ver': False,
        'verstatus': True,
        'imagestatus': True,
        'sup': False,
        'hidebar': False
    }

    if request.method == "POST":
        action = request.POST.get('action')

        if action == 'verify':
            uname = request.POST.get('uname')
            email = request.POST.get('email')
            password = request.POST.get('password')
            image = request.FILES.get('image')

            if image:
                path = f'temp_images/{os.path.basename(image.name)}'
                default_storage.save(path, ContentFile(image.read()))
                request.session['image_path'] = path

            request.session.update({'uname': uname, 'email': email, 'password': password})

            # Added role='general' correctly here:
            if UserProfile.objects.filter(user__username=uname, role='general').exists():
                context['unamecheck'] = False
                return render(request, 'index.html', context)
            if UserProfile.objects.filter(user__email=email, role='general').exists():
                context['emailcheck'] = False
                return render(request, 'index.html', context)

            ver_code = send_ver_code(email)
            if not ver_code:
                context.update({'hidebar': True})
                messages.error(request, "Failed to send verification code. Retry")
                return render(request, 'index.html', context)

            request.session['ver_code'] = ver_code
            context.update({'ver': True, 'verstatus': True, 'hidebar': True})
            messages.success(request, "Verification code sent.")
            return render(request, 'index.html', context)

        elif action == 'submit':
            if request.POST.get('inp_code') != request.session.get('ver_code'):
                messages.error(request, "Invalid verification code.")
                context.update({'ver': False, 'verstatus': False})
                return render(request, 'index.html', context)

            request.session.pop('ver_code', None)

            uname = request.session.get('uname')
            email = request.session.get('email')
            password = request.session.get('password')

            image = None
            if 'image_path' in request.session:
                path = request.session.pop('image_path')
                with default_storage.open(path) as img:
                    image = ContentFile(img.read(), name=os.path.basename(path))

            try:
                user = User.objects.create_user(username=uname, email=email, password=password)
                # Added role='general' here:
                UserProfile.objects.create(user=user, image=image, role='general')
            except IntegrityError:
                messages.error(request, "Registration failed. Try a different username or email.")
                return render(request, 'index.html', context)

            messages.success(request, "Registration successful.")
            context['sup'] = True
            return render(request, 'index.html', context)

    return render(request, 'index.html', context)

# Login
def loginpage(request):
    if request.method == "POST":

        if request.user.is_authenticated:
            logout(request)

        uname = request.POST.get('uname')
        password = request.POST.get('password')

        user = authenticate(request, username=uname, password=password)
        if not user:
            try:
                # Filter with role='general':
                u = UserProfile.objects.get(user__email=uname, role='general')
                user = authenticate(request, username=u.user.username, password=password)
            except UserProfile.DoesNotExist:
                user = None

        if user:
            login(request, user)
            return redirect('/')
        else:
            return render(request, 'login.html', {'check': False})

    return render(request, 'login.html', {'unameCheck': True, 'passwordCheck': True})


# Forgot Password (unchanged)
def forgetpassword(request):
    context = {'verification': False, 'ver': False, 'chstatus': False}

    if request.method == "POST":
        action = request.POST.get('action')
        email = request.POST.get('email')
        if action == 'verify':
            if not User.objects.filter(email=email).exists():
                messages.error(request, "Email not found.")
                return render(request, 'forgetpassword.html', context)

            ver_code = send_ver_code(email)
            if ver_code:
                request.session.update({'ver_code': ver_code, 'emailsave': email})
                context.update({'ver': True, 'chstatus': True})
                messages.success(request, "Verification code sent.")
            else:
                messages.error(request, "Failed to send code.")

        elif action == 'submit':
            if request.POST.get('inp_code') == request.session.get('ver_code'):
                context['verification'] = True
                request.session.pop('ver_code', None)
            else:
                messages.error(request, "Incorrect verification code.")
                context.update({'ver': True, 'chstatus': True})

    return render(request, 'forgetpassword.html', context)

# Reset Password (unchanged)
def newpassword(request):

    if request.method == "POST":
        pass1 = request.POST.get('pass1')
        pass2 = request.POST.get('pass2')
        email = request.session.pop('emailsave', None)

        if not email:
            return render(request, 'newpassword.html', {'emailerror': True})
        if pass1 != pass2:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'newpassword.html')

        try:
            user = User.objects.get(email=email)
            user.set_password(pass1)
            user.save()

            messages.success(request, "Password changed successfully.")
            return render(request, 'newpassword.html', {'ch_password': True})
        except User.DoesNotExist:
            return render(request, 'newpassword.html', {'emailerror': True})

    return render(request, 'newpassword.html')

# Creator Signup
def creatorsignup(request):
    context = {'hidebar': True, 'emailcheck': False, 'unamecheck': False, 'checkcomplete': False}
    if request.method == "POST":
        action = request.POST.get('action')

        if action == 'req':
            uname = request.POST.get('uname')
            email = request.POST.get('email')
            password = request.POST.get('password')
            image = request.FILES.get('image')

            # Added role='creator' filtering:
            uname_exists = User.objects.filter(username=uname).exists()
            email_exists = User.objects.filter(email=email).exists()

            if uname_exists:
                messages.error(request, "Creator with this Username already exists.")
                context.update({'hidebar': True, 'unamecheck': True})
                return render(request, 'creatorsignup.html', context)
            if email_exists:
                context.update({'hidebar': True, 'emailcheck': True})
                messages.error(request, "Creator with this Email already exists.")
                return render(request, 'creatorsignup.html', context)

            if image:
                path = f'temp_images/{os.path.basename(image.name)}'
                default_storage.save(path, ContentFile(image.read()))
                request.session['image_path'] = path

            request.session['cuname'] = uname
            request.session['cemail'] = email
            request.session['cpassword'] = password

            send_code = send_ver_code(email)
            if send_code is None:
                context.update({'hidebar': True})
                messages.error(request, "Error Sending Verification Code, Retry")
                return render(request, 'creatorsignup.html', context)

            request.session['ac_code'] = send_code
            messages.success(request, "Verification Code Sent Successfully")
            context.update({'hidebar': False})
            return render(request, 'creatorsignup.html', context)

        elif action == 'verify':
            ver_code = request.POST.get('ver_code')
            ch_code = request.session.get('ac_code')

            if ver_code != ch_code:
                messages.error(request, "Incorrect verification code, retry.")
                context.update({'hidebar': False})
                return render(request, 'creatorsignup.html', context)

            cuname = request.session.get('cuname')
            cemail = request.session.get('cemail')
            cpassword = request.session.get('cpassword')

            image = None
            if 'image_path' in request.session:
                path = request.session.pop('image_path')
                with default_storage.open(path, 'rb') as img_file:
                    image = ContentFile(img_file.read(), name=os.path.basename(path))

            try:
                # Create user with password correctly
                creator = User.objects.create_user(username=cuname, email=cemail, password=cpassword)
                # Add role='creator' here
                fcreator = UserProfile.objects.create(user=creator, image=image, role='creator')
                # If you have profile_image field on creator model, save here (optional)
                fcreator.save()
                login(request,creator)
            except IntegrityError:
                context.update({'hidebar': True})
                messages.error(request, "Registration failed. Try a different username or email.")
                return render(request, 'creatorsignup.html', context)

            context.update({'checkcomplete': True})
            messages.success(request, "Registration successful.")

            return render(request, 'creatorsignup.html', context)

    return render(request, 'creatorsignup.html', context)

@creator_required
def upload_project(request):
    if request.method == 'POST':
        name = request.POST.get('project_name')
        files = request.FILES.getlist('project_file')
        reqs = request.POST.get('requirements')
        desc = request.POST.get('description')

        user_profile = UserProfile.objects.get(user=request.user)

        project = MLProject.objects.create(
            creator=user_profile,
            project_name=name,
            requirements=reqs,
            description=desc,
        )

        for file in files:
            MLProjectFile.objects.create(project=project, file=file)

        return render(request, 'allmlproj.html', {'checkcomplete': True})

    return render(request, 'allmlproj.html')



@staff_member_required
def adminsignup(request):
    if request.method == 'POST':
        uname = request.POST.get('uname')
        email = request.POST.get('email')
        password = request.POST.get('password')
        image = request.FILES.get('image')

        # Check if username or email already exists with role 'admin'
        if UserProfile.objects.filter(user__username=uname, role='admin').exists():
            messages.error(request, "Admin with this username already exists.")
            return render(request, 'adminsignup.html')
        if UserProfile.objects.filter(user__email=email, role='admin').exists():
            messages.error(request, "Admin with this email already exists.")
            return render(request, 'adminsignup.html')

        # Save image temporarily if exists
        img_file = None
        if image:
            path = f'temp_images/{os.path.basename(image.name)}'
            default_storage.save(path, ContentFile(image.read()))
            with default_storage.open(path, 'rb') as img_open:
                img_file = ContentFile(img_open.read(), name=os.path.basename(path))

        # Create user and profile with role='admin'
        user = User.objects.create_user(username=uname, email=email, password=password)
        user.is_staff = True  # allows access to admin panel
        user.is_superuser = False  # adjust as needed
        user.save()

        UserProfile.objects.create(user=user, image=img_file, role='admin')

        messages.success(request, "Admin registered successfully.")
        return redirect('/login/')  # or any other page

    return render(request, 'adminsignup.html')
def creator_login(request):
    if request.user.is_authenticated:
        return redirect('/')

    if request.method == 'POST':
        uname = request.POST.get('username')
        pwd = request.POST.get('password')

        user = authenticate(request, username=uname, password=pwd)


        if user is not None:
            # Optional: Check if user is a creator (custom check if you have a user type)
            # if hasattr(user, 'profile') and user.profile.user_type == 'creator':
            dataset = UserProfile.objects.filter(user__username=uname, role='creator').exists()
            if not dataset:
                return redirect('/login/')
            login(request, user)
            return redirect('/')
        else:
            messages.error(request, 'Invalid username or password.')

    return render(request, 'creatorlogin.html')

@staff_member_required
def review_projects(request):
    projects = MLProject.objects.all().order_by('-submitted_at')
    return render(request, 'adminapprove.html', {'projects': projects})

@staff_member_required
def approve_project(request, project_id):
    project = get_object_or_404(MLProject, id=project_id)
    uname = project.creator.user.username
    email = project.creator.user.email
    project.is_approved = True
    project.save()
    if send_email_msg(True,uname,email):
        return render(request,'adminapprove.html',{'msgsuccess':True})
    return render(request,'adminapprove.html')

@staff_member_required
def reject_project(request, project_id):
    project = get_object_or_404(MLProject, id=project_id)
    uname=project.creator.user.username
    email=project.creator.user.email
    project.delete()
    if send_email_msg(False,uname,email):
        return render(request,'adminapprove.html',{'msgsuccess':True})
    return render(request,'adminapprove.html')
@creator_required
def creator_info(request, id):
    creator = UserProfile.objects.get(id=id)
    return JsonResponse({
        'username': creator.user.username,
        'email': creator.user.email,
        'bio': creator.role or '',
    })

def dashboard(request):
    projects = MLProject.objects.filter(is_approved=True).order_by('-submitted_at')
    context = {'projects': projects, 'is_creator': False}

    if request.user.is_authenticated and hasattr(request.user, 'userprofile'):
        context['is_creator'] = request.user.userprofile.role == 'creator'

    return render(request, 'display.html', context)

@login_required
def user_profile(request):
    return render(request, 'user_profile.html', {'user': request.user})
@login_required
def logout_func(request):
    logout(request)
    return redirect('/')
@creator_required
def creatorprojects(request):
    return render(request,'mlproj.html')

def get_creator_info(request, creator_id):
    profile = get_object_or_404(UserProfile, id=creator_id)
    user = profile.user

    data = {
        'username': user.username,
        'email': user.email,
        'profile_image_url': profile.image.url if profile.image else '',
    }
    return JsonResponse(data)



@login_required
def use_project(request, project_id):
    project = get_object_or_404(MLProject, id=project_id)

    # Get all files related to this project
    project_files = MLProjectFile.objects.filter(project=project)
    if project_id == 5:
    # Load the required files
        preprocessor = None
        model = None
        target_scaler = None

        for file in project_files:
            filename = os.path.basename(file.project_file.name)
            path = file.project_file.path

            if 'model' in filename and filename.endswith('.pkl'):
                model = joblib.load(path)
            elif 'column_transformer' in filename and filename.endswith('.pkl'):
                preprocessor = joblib.load(path)
            elif 'target_scaler' in filename and filename.endswith('.pkl'):
                target_scaler = joblib.load(path)

    if request.method == 'POST':
        if project_id == 5:
            age = float(request.POST.get('age'))
            sex = request.POST.get('sex')
            bmi = float(request.POST.get('bmi'))
            children = int(request.POST.get('child'))
            smoker = request.POST.get('smoker')
            region = request.POST.get('region')

            input_dict = {
                'age': age,
                'sex': sex,
                'bmi': bmi,
                'children': children,
                'smoker': smoker,
                'region': region
            }

            input_df = pd.DataFrame([input_dict])

            # Use the preprocessor (ColumnTransformer) here
            if preprocessor:
                input_processed = preprocessor.transform(input_df)
            else:
                input_processed = input_df.values  # fallback to raw values if no preprocessor

            prediction = model.predict(input_processed)

            if target_scaler:
                prediction = target_scaler.inverse_transform(prediction.reshape(-1, 1))

            return render(request, f'mlprojects/project_{project_id}.html', {
                'project': project,
                'predictcomp': True,
                'predictionmsg': f"Predicted Value: {prediction[0][0]:.2f}",
                'predictionaccuracy': "",
            })
    return render(request, f'mlprojects/project_{project_id}.html',{'project':project})


loaded_models = {}
@login_required
def get_model(project_id):
    if project_id not in loaded_models:
        project_files = MLProjectFile.objects.filter(project_id=project_id)
        if not project_files.exists():
            raise Exception("No model file found for this project")
        model_file = project_files.first()
        model_path = model_file.file.path
        with open(model_path, 'rb') as f:
            loaded_models[project_id] = pickle.load(f)
    return loaded_models[project_id]






@staff_member_required
def download_project_file(request, project_id):
    project = get_object_or_404(MLProject, id=project_id)
    files = project.files.all()  # Using the related_name="files" in your ForeignKey

    if not files:
        raise Http404("No files found for this project.")

    # Create a ZIP file in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
        for f in files:
            file_path = f.project_file.path
            filename = os.path.basename(file_path)
            zip_file.write(file_path, arcname=filename)

    zip_buffer.seek(0)
    response = HttpResponse(zip_buffer, content_type='application/zip')
    response['Content-Disposition'] = f'attachment; filename="{project.project_name}_files.zip"'
    return response

def aboutus(request):
    return render(request, 'aboutus.html', {'current_year': timezone.now().year})
