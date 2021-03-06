package helper

import (
	"sync"
	"time"

	"fmt"
	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"sort"
)

// Module specifics. This must be defined by each module
type Module struct {
	name string

	// Moduler implementation
	moduler Moduler

	// Module config
	Config ModuleConfig

	// List of all metricsets in this module. Use to keep track of metricsets
	metricSets map[string]*MetricSet

	// MetricSet waitgroup
	wg sync.WaitGroup

	done chan struct{}
}

// NewModule creates a new module
func NewModule(config ModuleConfig, moduler Moduler) *Module {
	return &Module{
		name:       config.Module,
		Config:     config,
		moduler:    moduler,
		metricSets: map[string]*MetricSet{},
		wg:         sync.WaitGroup{},
		done:       make(chan struct{}),
	}
}

// Starts the given module
func (m *Module) Start(b *beat.Beat) error {

	defer logp.Recover(fmt.Sprintf("Module %s paniced and stopped running.", m.name))

	if !m.Config.Enabled {
		logp.Debug("helper", "Not starting module %s with metricsets %s as not enabled.", m.name, m.getMetricSetsList())
		return nil
	}

	logp.Info("Setup moduler: %s", m.name)
	err := m.moduler.Setup()
	if err != nil {
		return fmt.Errorf("Error setting up module: %s. Not starting metricsets for this module.", err)
	}

	err = m.loadMetricsets()
	if err != nil {
		return fmt.Errorf("Error loading metricsets: %s", err)
	}

	// Setup period
	period, err := time.ParseDuration(m.Config.Period)
	if err != nil {
		return fmt.Errorf("Error in parsing period of metric %s: %v", m.name, err)
	}

	// If no period set, set default
	if period == 0 {
		logp.Info("Setting default period for metric %s as not set.", m.name)
		period = 1 * time.Second
	}

	// TODO: Improve logging information with list (names of metricSets)
	logp.Info("Start Module %s with metricsets [%s] and period %v", m.name, m.getMetricSetsList(), period)

	go m.Run(period, b)

	return nil
}

func (m *Module) Run(period time.Duration, b *beat.Beat) {
	ticker := time.NewTicker(period)

	defer func() {
		logp.Info("Stopped module %s with metricsets %s", m.name, m.getMetricSetsList())
		ticker.Stop()
	}()

	var wg sync.WaitGroup
	ch := make(chan struct{})

	wait := func() {
		wg.Wait()
		ch <- struct{}{}
	}

	// TODO: A fetch event should take a maximum until the next ticker and
	// be stopped before the next request is sent. If a fetch is not successful
	// until the next it means it is a failure and a "error" event should be sent to es
	fetch := func(set *MetricSet) {
		defer wg.Done()
		// Move execution part to module?
		m.FetchMetricSets(b, set)
	}

	for {
		// Waits for next ticker
		select {
		case <-m.done:
			return
		case <-ticker.C:
		}

		for _, set := range m.metricSets {
			wg.Add(1)
			go fetch(set)
		}
		go wait()

		// Waits until all fetches are finished
		select {
		case <-m.done:
			return
		case <-ch:
			// finished parallel fetch
		}
	}
}

func (m *Module) FetchMetricSets(b *beat.Beat, metricSet *MetricSet) {

	m.wg.Add(1)

	// Catches metric in case of panic. Keeps other metricsets running
	defer m.wg.Done()

	// Separate defer call as is has to be called directly
	defer logp.Recover(fmt.Sprintf("Metric %s paniced and stopped running.", m.name))

	events, err := metricSet.Fetch()

	if err != nil {
		// TODO: Also list module?
		logp.Err("Fetching events in MetricSet %s returned error: %s", metricSet.Name, err)
		// TODO: Still publish event with error
		return
	}

	events, err = m.processEvents(events, metricSet)

	// Async publishing of event
	b.Events.PublishEvents(events)

}

// Stop stops module and all its metricSets
func (m *Module) Stop() {
	logp.Info("Stopping module: %v", m.name)
	m.wg.Wait()
}

// loadMetricsets creates and setups the metricseter for the module
func (m *Module) loadMetricsets() error {
	// Setup - Create metricSets for the module
	for _, metricsetName := range m.Config.MetricSets {

		metricSet, err := Registry.GetMetricSet(m, metricsetName)
		if err != nil {
			return err
		}
		m.metricSets[metricsetName] = metricSet
	}
	return nil
}

// getMetricSetsList is a helper function that returns a list of all module metricsets as string
// This is mostly used for logging
func (m *Module) getMetricSetsList() string {

	// Sort list first alphabetically
	keys := make([]string, 0, len(m.metricSets))
	for key := range m.metricSets {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// Create output string
	list := ""
	first := true

	for _, value := range keys {
		if !first {
			list = list + ", "
		}
		first = false
		list = list + value
	}

	return list
}

func (m *Module) processEvents(events []common.MapStr, metricSet *MetricSet) ([]common.MapStr, error) {
	newEvents := []common.MapStr{}

	// Default name is empty, means it will be metricbeat
	indexName := ""
	typeName := "metricsets"
	timestamp := common.Time(time.Now())

	for _, event := range events {
		// Set meta information dynamic if set
		indexName = getIndex(event, indexName)
		typeName = getType(event, typeName)
		timestamp = getTimestamp(event, timestamp)

		// Each metricset has a unique eventfieldname to prevent type conflicts
		eventFieldName := m.name + "-" + metricSet.Name

		// TODO: Add fields_under_root option for "metrics"?
		event = common.MapStr{
			"type":         typeName,
			eventFieldName: event,
			"metricset":    metricSet.Name,
			"module":       m.name,
			"@timestamp":   timestamp,
		}

		// Overwrite index in case it is set
		if indexName != "" {
			event["beat"] = common.MapStr{
				"index": indexName,
			}
		}

		newEvents = append(newEvents, event)
	}

	return newEvents, nil
}
