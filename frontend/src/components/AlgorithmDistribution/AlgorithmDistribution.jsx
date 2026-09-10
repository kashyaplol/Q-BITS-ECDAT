import './AlgorithmDistribution.css'

function AlgorithmDistribution({ data }) {
  const maxCount = Math.max(...data.map((d) => d.count))

  return (
    <section className="algo-dist">
      <div className="panel-header">
        <h2>Algorithm distribution</h2>
        <span className="panel-header__hint">{data.length} algorithms</span>
      </div>

      <div className="algo-dist__bars">
        {data.map((item) => (
          <div className="algo-dist__row" key={item.algorithm}>
            <span className="algo-dist__label">{item.algorithm}</span>
            <div className="algo-dist__track">
              <div
                className="algo-dist__fill"
                style={{ width: `${(item.count / maxCount) * 100}%` }}
              />
            </div>
            <span className="algo-dist__count">{item.count}</span>
          </div>
        ))}
      </div>
    </section>
  )
}

export default AlgorithmDistribution
