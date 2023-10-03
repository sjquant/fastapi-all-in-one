FROM python:3.11-slim as base
RUN apt-get update && apt-get install --no-install-recommends -y build-essential
ENV PYTHONHASHSEED=random \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    POETRY_HOME=$HOME/.poetry \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_VIRTUALENVS_IN_PROJECT=false \
    WORKDIR=/code
ENV PATH="$POETRY_HOME/bin:$PATH" \
    TALIB_PREFIX=/opt/talib_c
ENV TA_LIBRARY_PATH=$TALIB_PREFIX/lib \
    TA_INCLUDE_PATH=$TALIB_PREFIX/include 
ENV PYTHONPATH="$PYTHONPATH:$WORKDIR"
WORKDIR $WORKDIR

FROM base as poetry_installer
RUN apt-get install --no-install-recommends -y curl
ENV POETRY_VERSION=1.5.1
RUN curl -sSL https://install.python-poetry.org | python3 -
COPY ./poetry.lock ./pyproject.toml ./
RUN poetry install --without dev

FROM base as prod
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY . .
RUN chmod +x scripts/*.sh
CMD uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 --no-access-log


