FROM python:3.7-alpine

ENV TIO_ACCESS_KEY ""
ENV TIO_SECRET_KEY ""
ENV AWS_REGION ""
ENV AWS_ACCOUNT_ID ""
ENV AWS_ACCESS_ID ""
ENV AWS_SECRET_KEY ""
ENV LOG_LEVEL ""
ENV OBSERVED_SINCE ""
ENV RUN_EVERY ""

COPY requirements.txt /

RUN pip install -r requirements.txt

COPY sechubingest.py /

CMD ["/sechubingest.py"]