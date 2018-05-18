package io.securecodebox.scanprocess.listener;

import io.securecodebox.constants.DefaultFields;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.camunda.bpm.engine.delegate.ExecutionListener;
import org.camunda.bpm.engine.variable.Variables;
import org.camunda.bpm.engine.variable.impl.value.ObjectValueImpl;
import org.camunda.bpm.engine.variable.value.ObjectValue;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class RemoveScanprocessListener implements ExecutionListener {

    protected static final org.slf4j.Logger LOG = LoggerFactory.getLogger(RemoveScanprocessListener.class);

    @Override
    public void notify(DelegateExecution delegateExecution) throws Exception {

        List<String> nextProcesses = (List<String>)delegateExecution.getVariable(DefaultFields.PROCESS_NEXT_SCANPROCESSES.name());
        String id = nextProcesses.remove(0);

        ObjectValue objectValue = Variables.objectValue(nextProcesses)
                .serializationDataFormat(Variables.SerializationDataFormats.JSON)
                .create();

        delegateExecution.setVariable(DefaultFields.PROCESS_NEXT_SCANPROCESSES.name(), objectValue);

        LOG.info("Removed scanprocess {}", id);
    }
}
