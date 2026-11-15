"""Offline projections; never change canonical source data or gateway behavior."""
from .contracts import REPRESENTATION  # Installs the existing data-plane import path.
import canonical_request as cr

PATH_VIEW = "target-path-neutralized/v1"


def neutralize_target_path(text):
    """Replace request-target path with '/', retaining query/body verbatim.

    Synthetic extraction view only, never a stored canonical training example.
    Path-like content in query/body remains. Absolute/authority forms are refused.
    """
    if type(text) is not str:
        raise TypeError("canonical text must be str")
    cr.parse_canonical(text)
    line, _, remainder = text.partition("\n")
    method, target_version = line.split(" ", 1)
    target = target_version[:-len(" HTTP/1.1")]
    if not (target.startswith("/") or target == "*"):
        raise ValueError("path projection requires origin or asterisk target")
    _, question, query = target.partition("?")
    return f"{method} /{question}{query} HTTP/1.1\n{remainder}"
