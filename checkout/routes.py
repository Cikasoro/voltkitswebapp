from flask import Blueprint

checkout_bp = Blueprint(
    "checkout",
    __name__,
    url_prefix="/checkout"
)
