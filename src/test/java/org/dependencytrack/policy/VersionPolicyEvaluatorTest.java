package org.dependencytrack.policy;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Project;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class VersionPolicyEvaluatorTest extends PersistenceCapableTest {

    private VersionPolicyEvaluator evaluator;

    @Before
    public void setUp() {
        evaluator = new VersionPolicyEvaluator();
    }

    @Test
    public void testLessThanOperator() {
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_LESS_THAN, "1.1.1");

        final var component = new Component();
        component.setGroup("Acme");
        component.setName("Test Component");

        // Component version is lower
        component.setVersion("1.1.0");
        Project project = new Project();
        project.setName("My Project");
        component.setName("Test Component");
        component.setProject(project);
        qm.persist(component);
        Assert.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is equal
        final var component1 = new Component();
        component1.setGroup("Acme");
        component1.setName("Test Component");
        component1.setVersion("1.1.1");
        component1.setProject(project);
        qm.persist(component1);
        Assert.assertEquals(0, evaluator.evaluate(policy, component1).size());

        // Component version is higher
        final var component2 = new Component();
        component2.setGroup("Acme");
        component2.setName("Test Component");
        component2.setVersion("1.1.2");
        component2.setVersion("1.1.1");
        component2.setProject(project);
        qm.persist(component2);
        Assert.assertEquals(0, evaluator.evaluate(policy, component2).size());
    }

    @Test
    public void testLessThanOrEqualOperator() {
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_LESSER_THAN_OR_EQUAL, "1.1.1");
        Project project = new Project();
        project.setName("My Project");
        final var component = new Component();
        component.setGroup("Acme");
        component.setName("Test Component");
        component.setProject(project);
        // Component version is lower
        component.setVersion("1.1.0");
        qm.persist(component);
        Assert.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is equal
        final var component1 = new Component();
        component1.setGroup("Acme");
        component1.setName("Test Component");
        component1.setProject(project);
        // Component version is lower
        component1.setVersion("1.1.1");
        qm.persist(component1);
        Assert.assertEquals(1, evaluator.evaluate(policy, component1).size());

        // Component version is higher
        final var component2 = new Component();
        component2.setGroup("Acme");
        component2.setName("Test Component");
        component2.setProject(project);
        component2.setVersion("1.1.2");
        qm.persist(component2);
        Assert.assertEquals(0, evaluator.evaluate(policy, component2).size());
    }

    @Test
    public void testEqualOperator() {
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_EQUAL, "1.1.1");
        Project project = new Project();
        project.setName("My Project");
        final var component = new Component();
        component.setGroup("Acme");
        component.setName("Test Component");
        component.setProject(project);
        // Component version is lower
        component.setVersion("1.1.0");
        qm.persist(component);
        Assert.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is equal
        final var component1 = new Component();
        component1.setGroup("Acme");
        component1.setName("Test Component");
        component1.setVersion("1.1.1");
        component1.setProject(project);
        qm.persist(component1);
        Assert.assertEquals(1, evaluator.evaluate(policy, component1).size());

        // Component version is higher
        final var component2 = new Component();
        component2.setGroup("Acme");
        component2.setName("Test Component");
        component2.setProject(project);
        qm.persist(component2);
        component.setVersion("1.1.2");
        Assert.assertEquals(0, evaluator.evaluate(policy, component2).size());
    }

    @Test
    public void testNotEqualOperator() {
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_NOT_EQUAL, "1.1.1");

        Project project = new Project();
        project.setName("My Project");
        final var component = new Component();
        component.setGroup("Acme");
        component.setName("Test Component");
        component.setProject(project);
        // Component version is lower
        component.setVersion("1.1.0");
        qm.persist(component);
        Assert.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is equal
        final var component1 = new Component();
        component1.setGroup("Acme");
        component1.setName("Test Component");
        component1.setProject(project);
        component1.setVersion("1.1.1");
        qm.persist(component1);
        Assert.assertEquals(0, evaluator.evaluate(policy, component1).size());

        // Component version is higher
        final var component2 = new Component();
        component2.setGroup("Acme");
        component2.setName("Test Component");
        component2.setProject(project);
        qm.persist(component2);
        component.setVersion("1.1.2");
        Assert.assertEquals(1, evaluator.evaluate(policy, component2).size());
    }

    @Test
    public void testGreaterThanOperator() {
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_GREATER_THAN, "1.1.1");
        Project project = new Project();
        project.setName("My Project");
        final var component = new Component();
        component.setGroup("Acme");
        component.setName("Test Component");
        component.setProject(project);
        // Component version is lower
        component.setVersion("1.1.0");
        qm.persist(component);
        Assert.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is equal
        final var component1 = new Component();
        component1.setName("Test Component");
        component1.setGroup("Acme");
        component1.setVersion("1.1.1");
        component1.setProject(project);
        qm.persist(component1);
        Assert.assertEquals(0, evaluator.evaluate(policy, component1).size());

        // Component version is higher
        final var component2 = new Component();
        component2.setName("Test Component");
        component2.setGroup("Acme");
        component2.setVersion("1.1.2");
        component2.setProject(project);
        qm.persist(component2);
        Assert.assertEquals(1, evaluator.evaluate(policy, component2).size());
    }

    @Test
    public void testGreaterThanOrEqualOperator() {
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "1.1.1");
        Project project = new Project();
        project.setName("My Project");
        final var component = new Component();
        component.setGroup("Acme");
        component.setName("Test Component");
        component.setProject(project);
        // Component version is lower
        component.setVersion("1.1.0");
        qm.persist(component);
        Assert.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is equal
        final var component1 = new Component();
        component1.setGroup("Acme");
        component1.setName("Test Component");
        component1.setProject(project);
        // Component version is lower
        component1.setVersion("1.1.1");
        qm.persist(component1);
        Assert.assertEquals(1, evaluator.evaluate(policy, component1).size());

        // Component version is higher
        final var component2 = new Component();
        component2.setGroup("Acme");
        component2.setName("Test Component");
        component2.setProject(project);
        // Component version is lower

        component2.setVersion("1.1.2");
        qm.persist(component2);
        Assert.assertEquals(1, evaluator.evaluate(policy, component2).size());
    }

}