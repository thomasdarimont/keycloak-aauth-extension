<#import "template.ftl" as layout>
<#import "buttons.ftl" as buttons>

<#macro consentForm>
    <form class="${properties.kcFormClass!} ${properties.kcMarginTopClass!}" action="${aauth.consentActionUrl}" method="POST">
        <input type="hidden" name="consent_code" value="${aauth.consentCode}">
        <@buttons.actionGroup horizontal=true>
            <@buttons.button id="kc-login" name="accept" label="doYes"/>
            <@buttons.button id="kc-cancel" name="cancel" label="doNo" type="secondary"/>
        </@buttons.actionGroup>
    </form>
</#macro>

<@layout.registrationLayout bodyClass="oauth"; section>
    <#if section = "header">
        <p>${msg("aauthConsentTitle")}</p>
    <#elseif section = "form">
        <div id="kc-oauth" class="content-area">
            <h3>${msg("aauthConsentRequest")}</h3>
            <p><strong>${msg("aauthConsentAgent")}:</strong> ${aauth.agentId}</p>
            <#if aauth.resourceId?has_content>
                <p><strong>${msg("aauthConsentResource")}:</strong> ${aauth.resourceId}</p>
            </#if>
            <#if aauth.scopes?has_content>
                <h3>${msg("aauthConsentScopes")}</h3>
                <p>${msg("aauthConsentDescription")}</p>
                <ul class="${properties.kcListClass!}">
                    <#list aauth.scopes as scope>
                        <li><span>${scope}</span></li>
                    </#list>
                </ul>
            </#if>

            <#if aauth.clarificationEnabled>
                <hr/>
                <#if aauth.awaitingResponse>
                    <div id="kc-aauth-clarification-waiting">
                        <h4>${msg("aauthClarificationWaiting")}</h4>
                        <p><strong>${msg("aauthClarificationYourQuestion")}:</strong> ${aauth.clarification!}</p>
                        <p><em>${msg("aauthClarificationWaitingHint")}</em></p>
                        <@buttons.buttonLink id="kc-aauth-refresh" href="${aauth.refreshUrl!}"
                                             label="aauthClarificationRefresh" class=["kcButtonSecondaryClass"]/>
                    </div>
                <#elseif aauth.clarification?has_content && aauth.clarificationResponse?has_content>
                    <div id="kc-aauth-clarification-answered">
                        <h4>${msg("aauthClarificationTitle")}</h4>
                        <p><strong>${msg("aauthClarificationYourQuestion")}:</strong> ${aauth.clarification}</p>
                        <p><strong>${msg("aauthClarificationAgentResponse")}:</strong> ${aauth.clarificationResponse}</p>
                    </div>
                    <@consentForm/>
                <#else>
                    <div id="kc-aauth-clarification-form">
                        <h4>${msg("aauthClarificationTitle")}</h4>
                        <p>${msg("aauthClarificationPrompt")}</p>
                        <form class="${properties.kcFormClass!}" action="${aauth.clarifyActionUrl}" method="POST">
                            <input type="hidden" name="pending_request_id" value="${aauth.pendingRequestId!}">
                            <input type="hidden" name="interaction_code" value="${aauth.interactionCode!}">
                            <input type="hidden" name="callback_url" value="${aauth.callbackUrl!}">
                            <input type="hidden" name="state" value="${aauth.state!}">
                            <div class="${properties.kcFormGroupClass!}">
                                <span class="${properties.kcInputClass!}">
                                    <textarea id="kc-aauth-clarification-question" name="clarification_question" rows="3"
                                              placeholder="${msg("aauthClarificationPlaceholder")}"></textarea>
                                </span>
                            </div>
                            <@buttons.actionGroup horizontal=true>
                                <@buttons.button id="kc-aauth-clarify-submit" label="aauthClarificationSubmit"/>
                            </@buttons.actionGroup>
                        </form>
                        <hr/>
                    </div>
                    <@consentForm/>
                </#if>
            <#else>
                <@consentForm/>
            </#if>
        </div>
    </#if>
</@layout.registrationLayout>
