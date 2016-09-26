package com.epam.dlab.backendapi;

import com.epam.dlab.backendapi.core.RESTService;
import com.epam.dlab.backendapi.dao.MongoService;
import com.epam.dlab.backendapi.resources.LoginResource;
import io.dropwizard.Application;
import io.dropwizard.assets.AssetsBundle;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;

import static com.epam.dlab.backendapi.SelfServiceApplicationConfiguration.SECURITY_SERVICE;

/**
 * Created by Alexey Suprun
 */
public class SelfServiceApplication extends Application<SelfServiceApplicationConfiguration> {
    public static void main(String... args) throws Exception {
        new SelfServiceApplication().run(args);
    }

    @Override
    public void initialize(Bootstrap<SelfServiceApplicationConfiguration> bootstrap) {
        super.initialize(bootstrap);
        bootstrap.addBundle(new AssetsBundle("/webapp/", "/webapp"));
    }

    @Override
    public void run(SelfServiceApplicationConfiguration configuration, Environment environment) throws Exception {
        MongoService mongoService = configuration.getMongoFactory().build(environment);
        RESTService securityService = configuration.getSecurityFactory().build(environment, SECURITY_SERVICE);
        environment.jersey().register(new LoginResource(mongoService, securityService));
    }
}