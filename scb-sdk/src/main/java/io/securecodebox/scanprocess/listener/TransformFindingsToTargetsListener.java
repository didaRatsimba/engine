package io.securecodebox.scanprocess.listener;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.securecodebox.constants.DefaultFields;
import io.securecodebox.model.Attribute;
import io.securecodebox.model.execution.Target;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.camunda.bpm.engine.delegate.ExecutionListener;
import org.camunda.bpm.engine.variable.Variables;
import org.camunda.bpm.engine.variable.value.ObjectValue;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;
import java.util.List;

@Component
public class TransformFindingsToTargetsListener implements ExecutionListener {

    protected static final org.slf4j.Logger LOG = LoggerFactory.getLogger(TransformFindingsToTargetsListener.class);

    @Override
    public void notify(DelegateExecution delegateExecution) throws Exception {

        try{
            ObjectMapper objectMapper = new ObjectMapper();
            String findingsAsString = objectMapper.writeValueAsString(delegateExecution.getVariable(
                    DefaultFields.PROCESS_FINDINGS.name()));
            List<Target> newTargets = objectMapper.readValue(objectMapper.readValue(findingsAsString, String.class),
                    objectMapper.getTypeFactory().constructCollectionType(List.class, Target.class));

            if(delegateExecution.getVariable(DefaultFields.PROCESS_ATTRIBUTE_MAPPING.name()) != null) {
                List<Attribute> attributeMapping = objectMapper.readValue((String) delegateExecution.getVariable(
                        DefaultFields.PROCESS_ATTRIBUTE_MAPPING.name()),
                        objectMapper.getTypeFactory().constructCollectionType(List.class, Attribute.class));

                //todo: The location mapping is just a workaround
                //todo: We should find a better way to map attributes to target field names and vice versa (maybe through reflection and comparing field names)
                //todo: Currently it's not allowed to have an attribute named "location"
                for (Target target : newTargets) {
                    for (Attribute attribute : attributeMapping) {
                        Object value = (attribute.getFrom().equals("location") ? target.getLocation() : target.getAttributes().get(attribute.getFrom()));
                        if (value != null) {
                            if(attribute.getTo().equals("location")){
                                target.setLocation((String)value);
                            }
                            else if(attribute.getFrom().equals("location")){
                                target.getAttributes().remove(attribute.getTo());
                                target.getAttributes().put(attribute.getTo(), value);
                            }
                            else {
                                target.getAttributes().remove(attribute.getFrom());
                                target.getAttributes().put(attribute.getTo(), value);
                            }
                        }
                    }
                }
            }

            LOG.info("Created Targets out of Findings: " + newTargets);


            ObjectValue objectValue = Variables.objectValue(objectMapper.writeValueAsString(newTargets))
                    .serializationDataFormat(Variables.SerializationDataFormats.JSON)
                    .create();
            delegateExecution.setVariable(DefaultFields.PROCESS_TARGETS.name(), objectValue);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Can't write field to process!", e);
        }
    }
}
