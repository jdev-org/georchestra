<%@ page language="java" pageEncoding="UTF-8" %>

<c:choose>
    <c:when test='<%= request.getParameter("noheader") == null %>'>
    <div id="go_head">
        <!-- Unused -->
        <geor-header legacy-header="${useLegacyHeader}" legacy-url="${headerUrl}" style="width:100%;height:${headerHeight}px;border:none;" active-app="console"></geor-header>
        <script src="${headerScript}"></script>
    </div>
    </c:when>
</c:choose>
