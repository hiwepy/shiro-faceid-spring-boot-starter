package org.apache.shiro.spring.boot;

import org.apache.shiro.spring.web.config.AbstractShiroWebConfiguration;
import org.springframework.beans.BeansException;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.baomidou.kisso.SSOAuthorization;
import com.baomidou.kisso.common.auth.AuthDefaultImpl;
import com.baomidou.kisso.web.handler.KissoDefaultHandler;
import com.baomidou.kisso.web.handler.SSOHandlerInterceptor;

//https://blog.csdn.net/weixin_42058600/article/details/81837056
@Configuration
@AutoConfigureBefore( name = {
	"org.apache.shiro.spring.config.web.autoconfigure.ShiroWebAutoConfiguration",  // shiro-spring-boot-web-starter
	"org.apache.shiro.spring.boot.ShiroBizWebAutoConfiguration" // spring-boot-starter-shiro-biz
})
@ConditionalOnProperty(prefix = ShiroFaceIDProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ ShiroFaceIDProperties.class })
public class ShiroFaceIDWebAutoConfiguration extends AbstractShiroWebConfiguration implements ApplicationContextAware {

	private ApplicationContext applicationContext;
	
	@Bean
	@ConditionalOnMissingBean
	public SSOAuthorization kissoAuthorization() {
		return new AuthDefaultImpl();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public SSOHandlerInterceptor kissoHandlerInterceptor() {
		return new KissoDefaultHandler();
	}
	
	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}

}
