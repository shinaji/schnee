import nox

#  Define the sessions to run by default.
nox.options.sessions = ["lint", "type_check", "test"]


@nox.session(venv_backend="none")
def lint(session: nox.Session) -> None:
    """Run ruff lint and format check."""
    args = session.posargs or []
    session.run("ruff", "check", *args)
    session.run("ruff", "format", "--check", *args)


@nox.session(venv_backend="none")
def type_check(session: nox.Session) -> None:
    """Run ty type check."""
    args = session.posargs or []
    session.run("ty", "check", *args)


@nox.session(venv_backend="none")
def test(session: nox.Session) -> None:
    """Run pytest."""
    args = session.posargs or []
    session.run("pytest", *args)
