from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    path("register/", views.register, name="register"),
    path("verify/<str:token>/", views.verify, name="verify"),
    path("login/", views.login, name="login"),
    path("logout/", views.logout, name="logout"),
    path("password-reset/", views.password_reset_request, name="password_reset"),
    path(
        "password-reset/<str:token>/",
        views.password_reset_confirm,
        name="password_reset_confirm",
    ),
    path("profile/", views.profile, name="profile"),
]
