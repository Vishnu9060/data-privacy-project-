import { Component } from 'react'

// Catches rendering crashes anywhere below it so one broken widget (e.g. a
// page choking on an unexpected API response shape) shows a recoverable
// error message instead of blanking the entire app to a white/black screen.
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    console.error('NETSEC AI crashed:', error, info)
  }

  render() {
    if (this.state.error) {
      return (
        <div className="crash-panel">
          <h2>Something went wrong on this page</h2>
          <p>{String(this.state.error.message || this.state.error)}</p>
          <button className="btn" onClick={() => this.setState({ error: null })}>
            Try again
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
