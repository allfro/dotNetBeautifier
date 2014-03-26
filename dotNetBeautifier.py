from urllib import unquote, quote
import re

from burp import (IBurpExtender, IProxyListener, IInterceptedProxyMessage, IParameter, IHttpListener,
                  IBurpExtenderCallbacks, IContextMenuFactory, IContextMenuInvocation)
from javax.swing import JMenuItem
from java.util import ArrayList


__author__ = 'Nadeem Douba'
__copyright__ = 'Copyright 2012, dotNetBeautifier Project'
__credits__ = []

__license__ = 'GPL'
__version__ = '0.2'
__maintainer__ = 'Nadeem Douba'
__email__ = 'ndouba@gmail.com'
__status__ = 'Development'


class BurpExtender(IBurpExtender, IProxyListener, IHttpListener, IContextMenuFactory):

    headerRegex = re.compile(r'X-dotNet-Beautifier:\s*(\d+(?:.\d+)?);')

    def registerExtenderCallbacks(self, callbacks):
        """
        Register our callbacks and create the necessary data structures for tracking messages.
        """
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._tracker = {}
        self._counter = {}
        self._messageReference = float(0)

        callbacks.setExtensionName('.NET Beautifier')
        callbacks.registerProxyListener(self)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        """
        Creates a context menu for beautifying and unbeautifying the request in editable message windows.
        """
        if invocation.getToolFlag() not in [
            IBurpExtenderCallbacks.TOOL_REPEATER, IBurpExtenderCallbacks.TOOL_PROXY,
            IBurpExtenderCallbacks.TOOL_INTRUDER
        ]:
            return

        if invocation.getInvocationContext() != IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            return

        menuItemList = ArrayList()
        messageInfo = invocation.getSelectedMessages()[0]
        requestBytes = messageInfo.getRequest()
        requestInfo = self._helpers.analyzeRequest(requestBytes)
        messageReference = self._getMessageReferenceFromBeautifyHeader(requestInfo, requestBytes)
        if messageReference != -1:
            def _unbeautifyClick(event):
                self._restoreParameters(messageReference, messageInfo)
            menuItemList.add(JMenuItem('Unbeautify Request', actionPerformed=_unbeautifyClick))
        else:
            self._messageReference += 1
            def _beautifyClick(event):
                self._simplifyParameters(self._messageReference, messageInfo)
            menuItemList.add(JMenuItem('Beautify Request', actionPerformed=_beautifyClick))
        return menuItemList

    def processProxyMessage(self, messageIsRequest, message):
        """
        Beautifies and unbeautifies messages being intercepted by the Proxy tool.
        """
        if messageIsRequest:
            self.processRequestMessage(message)
        else:
            self.processResponseMessage(message)

    def processRequestMessage(self, interceptedMessage):
        """
        Beautifies and unbeautifies messages being intercepted by the Proxy tool. The first time a message enters the
        Proxy chain, it is beautified and marked for rehooking. After the message is beautified, the user is given the
        opportunity to modify the HTTP message in the Burp Proxy tool. Once a message is forwarded, it is reprocessed
        in this method, gets unbeautified, and forwarded to the web server.
        """
        messageReference = interceptedMessage.getMessageReference()
        if interceptedMessage.getMessageReference() not in self._tracker:
            self._simplifyParameters(messageReference, interceptedMessage.getMessageInfo())
            interceptedMessage.setInterceptAction(IInterceptedProxyMessage.ACTION_FOLLOW_RULES_AND_REHOOK)
        else:
            self._restoreParameters(messageReference, interceptedMessage.getMessageInfo())
            interceptedMessage.setInterceptAction(IInterceptedProxyMessage.ACTION_DONT_INTERCEPT)

    def processResponseMessage(self, message):
        pass

    def _simplifyParameters(self, messageReference, messageInfo):
        """
        Simplifies .NET parameter names that are extremely long containing dollar signs ('$'). First the parameter's
        name is split using the dollar sign ('$') as a delimiter. The last element in the split string array is taken
        and used as the simplified parameter name. If the simplified parameter name is already in use, an index will
        be appended to the name as well (i.e. param[0], ..., param[n]) to avoid collisions.
        """
        requestBytes = self._addBeautifyHeader(messageReference, messageInfo.getRequest())
        requestInfo = self._helpers.analyzeRequest(requestBytes)

        if messageReference not in self._tracker:
            self._tracker[messageReference] = {}
            self._counter[messageReference] = {}

        parameters = requestInfo.getParameters()

        for i in range(len(parameters)):
            parameter = parameters.get(i)

            if parameter.getType() not in [IParameter.PARAM_BODY, IParameter.PARAM_URL,
                                           IParameter.PARAM_MULTIPART_ATTR]:
                continue
            parameterName = parameter.getName()
            value = None
            if '$' in unquote(parameterName):
                simplifiedParameterName = quote(unquote(parameterName).split('$')[-1])
            elif unquote(parameterName) in ['__VIEWSTATE', '__PREVIOUSPAGE', '__EVENTVALIDATION']:
                simplifiedParameterName = parameterName
                value = '<snipped out for sanity>'
            else:
                continue
            if simplifiedParameterName in self._tracker[messageReference]:
                if simplifiedParameterName not in self._counter[messageReference]:
                    self._counter[messageReference] = {simplifiedParameterName: 0}

                self._counter[messageReference][simplifiedParameterName] += 1
                simplifiedParameterName = '%s[%d]' % (
                    simplifiedParameterName, self._counter[messageReference][simplifiedParameterName])
            self._tracker[messageReference][simplifiedParameterName] = parameter

            if simplifiedParameterName != parameterName:
                requestBytes = self._rewriteName(parameter, simplifiedParameterName, requestBytes)
                requestInfo = self._helpers.analyzeRequest(requestBytes)
            if value:
                requestBytes = self._rewriteValue(parameter, value, requestBytes)
                requestInfo = self._helpers.analyzeRequest(requestBytes)
            parameters = requestInfo.getParameters()
        messageInfo.setRequest(self._helpers.buildHttpMessage(
            requestInfo.getHeaders(),
            requestBytes[requestInfo.getBodyOffset():])
        )

    def _removeBeautifyHeader(self, requestBytes):
        """
        Removes the temporary X-dotNet-Beautifier HTTP header before the request is issued to the web server.
        """
        requestInfo = self._helpers.analyzeRequest(requestBytes)
        headers = requestInfo.getHeaders()
        header = None
        for h in headers:
            if h.startswith('X-dotNet-Beautifier'):
                header = h
                break
        if header:
            headers.remove(header)
        return self._helpers.buildHttpMessage(headers, requestBytes[requestInfo.getBodyOffset():])

    def _rewriteName(self, p, newName, requestBytes):
        """
        Rewrites .NET parameter names.
        """
        requestString = self._helpers.bytesToString(requestBytes)
        start, end = p.getNameStart(), p.getNameEnd()
        return self._helpers.stringToBytes('%s%s%s' % (requestString[:start], newName, requestString[end:]))

    def _rewriteValue(self, p, newValue, requestBytes):
        """
        Rewrites the value of the .NET __VIEWSTATE, __PREVIOUSPAGE, and __EVENTVALIDATION
        parameters.
        """
        requestString = self._helpers.bytesToString(requestBytes)
        start, end = p.getValueStart(), p.getValueEnd()
        return self._helpers.stringToBytes('%s%s%s' % (requestString[:start], newValue, requestString[end:]))

    def _addBeautifyHeader(self, messageReference, requestBytes):
        """
        Adds a temporary X-dotNet-Beautifier HTTP header. The header is used to retrieve the
        original request parameter names when the beautified request is being restored. The header is removed once
        a request is unbeautified.
        """
        requestInfo = self._helpers.analyzeRequest(requestBytes)
        headers = requestInfo.getHeaders()
        headers.add('X-dotNet-Beautifier: %s; DO-NOT-REMOVE' % messageReference)
        return self._helpers.buildHttpMessage(headers, requestBytes[requestInfo.getBodyOffset():])

    def _restoreParameters(self, messageReference, messageInfo):
        """
        Unbeautifies the request by restoring the original .NET parameter names and values. Also removes the temporary
        X-dotNet-Beautifier HTTP header.
        """
        requestBytes = self._removeBeautifyHeader(messageInfo.getRequest())
        requestInfo = self._helpers.analyzeRequest(requestBytes)
        parameters = requestInfo.getParameters()
        for i in range(len(parameters)):
            simplifiedParameter = parameters.get(i)
            if simplifiedParameter.getType() not in [IParameter.PARAM_BODY, IParameter.PARAM_URL]:
                continue
            simplifiedParameterName = simplifiedParameter.getName()
            if simplifiedParameterName in self._tracker[messageReference]:
                originalParameter = self._tracker[messageReference][simplifiedParameterName]

                if simplifiedParameterName in ['__VIEWSTATE', '__PREVIOUSPAGE', '__EVENTVALIDATION']:
                    requestBytes = self._rewriteValue(simplifiedParameter, originalParameter.getValue(), requestBytes)
                    requestInfo = self._helpers.analyzeRequest(requestBytes)
                else:
                    requestBytes = self._rewriteName(simplifiedParameter, originalParameter.getName(), requestBytes)
                    requestInfo = self._helpers.analyzeRequest(requestBytes)
                parameters = requestInfo.getParameters()
        messageInfo.setRequest(self._helpers.buildHttpMessage(
            requestInfo.getHeaders(),
            requestBytes[requestInfo.getBodyOffset():])
        )

    def _getMessageReferenceFromBeautifyHeader(self, requestInfo, requestBytes):
        """
        Parses the X-dotNet-Beautifier HTTP header to retrieve the message reference identifier.
        """
        results = self.headerRegex.search(self._helpers.bytesToString(requestBytes[:requestInfo.getBodyOffset()]))
        if results:
            value = results.groups()[0]
            return float(value) if '.' in value else int(value)
        return -1

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        Used to unbeautify requests that are being issued by tools other than the Proxy tool in BurpSuite. For example,
        a beautified request may be issued by the Intruder, Repeater, and Sequencer tabs. In those cases, the message
        will be unbeautified prior to issuing the request to the web server.
        """
        if not messageIsRequest or toolFlag == IBurpExtenderCallbacks.TOOL_PROXY:
            return

        requestBytes = messageInfo.getRequest()
        requestInfo = self._helpers.analyzeRequest(requestBytes)

        messageReference = self._getMessageReferenceFromBeautifyHeader(requestInfo, requestBytes)
        if messageReference != -1:
            self._restoreParameters(messageReference, messageInfo)